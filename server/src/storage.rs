use std::{collections::{HashMap, HashSet}, fs::{self, File, OpenOptions}, io::{Cursor, Read, Write}, path::Path, str::FromStr};

use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, Timelike, Utc};
use http::{request::Builder, Uri};
use http_body_util::BodyExt;
use octocrab::{repos::releases::MakeLatest, Octocrab};
use reqwest::Method;
use rsa::{sha2::Sha512_256, Oaep};
use zip::{write::{FullFileOptions, SimpleFileOptions}, AesMode, CompressionMethod, ZipArchive, ZipWriter};

use crate::{config::{Storage, StorageEncyptionKey}, utils::remove_path};

// FIXME: support file permissions (for UNIX)

pub(crate) enum EncryptionMode<'a> {
    Password(&'a str),
    RSA(&'a StorageEncyptionKey),
}

impl<'a> EncryptionMode<'a> {

    fn compress_and_encrypt(&self, raw: &[u8], file_name: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            EncryptionMode::Password(pw) => {
                let mut storage = Cursor::new(vec![]);
                let mut zip = ZipWriter::new(&mut storage);
                zip.start_file(file_name, FullFileOptions::default().compression_method(CompressionMethod::Bzip2).large_file(true).with_aes_encryption(AesMode::Aes256, pw))?;
                zip.write_all(raw)?;
                zip.finish()?;
                let content = storage.into_inner();
                Ok(content)
            },
            EncryptionMode::RSA(key) => {
                let mut storage = Cursor::new(vec![]);
                let mut zip = ZipWriter::new(&mut storage);
                zip.start_file(file_name, FullFileOptions::default().compression_method(CompressionMethod::Bzip2).large_file(true))?;
                zip.write_all(raw)?;
                zip.finish()?;
                let content = storage.into_inner();
                let mut rng = rand::thread_rng();
                let enc = key.key.to_public_key().encrypt(&mut rng, Oaep::new::<Sha512_256>(), &content)?;
                Ok(enc)
            },
        }
    }

    fn decompress_and_decrypt(&self, raw: &[u8], token_hash: &str) -> anyhow::Result<Vec<u8>> {
        let path = format!("./nas/tmp/{token_hash}_dload.zip");
        fs::write(&path, raw)?;
        match self {
            EncryptionMode::Password(passwd) => {
                todo!()
            },
            EncryptionMode::RSA(key) => {
                let mut zip_archive = ZipArchive::new(OpenOptions::new().read(true).open(&path)?)?;
                let file = zip_archive.by_index(0)?;
                let bytes = file.bytes().try_collect::<Vec<u8>>()?;
                Ok(key.key.decrypt(Oaep::new::<Sha512_256>(), &bytes)?)
            },
        }
    }

}

impl Storage {

    pub(crate) async fn save_file(&self, key: EncryptionMode<'_>, update_start: DateTime<Utc>, token_hash: &str, file_name: &str, content: Option<&[u8]>, remaining_bytes: u64) -> anyhow::Result<()> {
        let content = content.map(|raw| key.compress_and_encrypt(raw, file_name).unwrap());
        let content = content.as_deref();
        match &self.method {
            crate::config::StorageMethod::LocalDisk => {
                let time = format!("v{}.{}.{}.{}", update_start.year(), update_start.month(), update_start.day(), update_start.hour());
                if let Some(parent) = Path::new(file_name).parent() {
                    fs::create_dir_all(format!(
                        "./nas/instances/{}/storage/{}/{}",
                        token_hash,
                        &time,
                        parent.to_str().unwrap()
                    ))?;
                }
                let tmp_path = format!(
                    "./nas/tmp/{}_{}",
                    token_hash,
                    Path::new(&file_name)
                        .file_name()
                        .map(|name| name.to_str().unwrap())
                        .unwrap_or(file_name)
                );
                match content {
                    Some(content) => {
                        OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open(&tmp_path)
                            .unwrap()
                            .write_all(&content)?;
                        let last_frame = remaining_bytes == 0;
                        if last_frame {
                            // replace original file
                            fs::copy(
                                &tmp_path,
                                &format!("./nas/instances/{}/storage/{}/{}", token_hash, &time, file_name),
                            )?;
                            // clean up tmp file
                            fs::remove_file(&tmp_path)?;
                        }
                    }
                    None => {
                        remove_path(&format!(
                            "./nas/instances/{}/storage/{}/{}",
                            token_hash, &time, file_name
                        ))?;
                    }
                }
                Ok(())
            },
            crate::config::StorageMethod::Github { token, name } => {
                let client = Octocrab::builder().personal_token(token.clone()).build()?;
                let repo = client.repos(name, token_hash);
                let releases = repo.releases();
                let latest = releases.get_latest().await?;
                let expected = format!("v{}.{}.{}.{}", update_start.year(), update_start.month(), update_start.day(), update_start.hour());
                if latest.tag_name != expected {
                    releases.create(&expected).make_latest(MakeLatest::True).draft(false).prerelease(false).send().await?;
                }
                let release_id = releases.get_latest().await?.id.to_string();
                if let Some(content) = content {
                    upload_asset_release(&client, name, token_hash, &release_id, file_name, None, content).await;
                } else {
                    upload_asset_release(&client, name, token_hash, &release_id, file_name, Some("delete"), &[]).await;
                }
                Ok(())
            },
        }
    }

    pub(crate) async fn try_recombine_backup(&self, key: EncryptionMode<'_>, token_hash: &str, latest_usable: u64, max_size: u64) -> Result<(), u64> {
        match &self.method {
            crate::config::StorageMethod::LocalDisk => {
                let mut size = 0;
                let mut computed = HashSet::new();
                for delta in fs::read_dir(&format!("./nas/instances/{token_hash}/storage")).unwrap() {
                    let name = delta.as_ref().unwrap().file_name();
                    let name = name.to_str().unwrap();
                    if parse_tag(name) <= latest_usable {
                        calc_dir_size(&mut size, delta.unwrap().path(), &mut computed).unwrap();
                    }
                }
                // FIXME: check size and construct backup zip if applicable
                if size > max_size {
                    return Err(size);
                }
                return Ok(());
            },
            crate::config::StorageMethod::Github { token, name } => {
                let octocrab = Octocrab::builder().personal_token(token.to_string()).build().unwrap();                
                let mut entries = HashMap::new();
                for release in octocrab.repos(name, token_hash).releases().list().per_page(100).send().await.unwrap() {
                    let date = release.tag_name;
                    let date_ms = parse_tag(&date);
                        if date_ms <= latest_usable {
                            for asset in release.assets {
                                if let Some((_, ms, _)) = entries.get(&asset.name) {
                                    if date_ms < *ms {
                                        continue;
                                    }
                                }
                                entries.insert(asset.name, (asset.browser_download_url, date_ms, asset.size as u64));
                            }
                        }
                }
                let mut size = 0;
                for (.., asset_size) in entries.values() {
                    size += *asset_size;
                }
                if size > max_size {
                    return Err(size);
                }
                let mut file = File::create_new(&format!("./nas/tmp/backups/{}.zip", token_hash)).unwrap();
                let mut zip = ZipWriter::new(&mut file);
                let mut dirs = HashSet::new();
                for path in entries.keys() {
                    for p in Path::new(path).ancestors().skip(1) {
                        // skip over "" and "/"
                        if p.to_str().unwrap().is_empty() || p.to_str().unwrap() == "/" {
                            break;
                        }
                        dirs.insert(p.to_str().unwrap().to_string());
                    }
                }

                let mut dirs = dirs.into_iter().collect::<Vec<_>>();
                dirs.sort_by(|first, second| first.chars().filter(|c| *c == '/').count().cmp(&second.chars().filter(|c| *c == '/').count()));
                for dir in dirs {
                    zip.add_directory_from_path(dir, SimpleFileOptions::default()).unwrap();
                }
                for (path, (url, date_ms, size)) in entries.iter() {
                    const FOUR_GB: u64 = 1024 * 1024 * 1024 * 4;
                    let dt = DateTime::from_timestamp_millis(*date_ms as i64).unwrap();
                    let dt = zip::DateTime::from_date_and_time(dt.year() as u16, dt.month() as u8, dt.day() as u8, dt.hour() as u8, dt.minute() as u8, dt.second() as u8).unwrap();
                    zip.start_file_from_path(path, FullFileOptions::default().large_file(*size >= FOUR_GB).last_modified_time(dt)).unwrap();
                    let mut val = octocrab._post(Uri::from_str(url.as_str()).unwrap(), Option::<&()>::None).await.unwrap().into_body();
                    while let Some(frame) = val.frame().await {
                        zip.write_all(&frame.unwrap().into_data().unwrap()).unwrap();
                    }
                }
                zip.finish().unwrap();
                
                // FIXME: check size and construct backup zip if applicable
                Ok(())
            },
        }
    }

}

fn parse_tag(tag: &str) -> u64 {
    let (y, m, d, h) = {
        let mut iter = (&tag[1..]).split('.');
        let ret = (iter.next().unwrap().parse::<u32>().unwrap() as i32, iter.next().unwrap().parse::<u32>().unwrap(), iter.next().unwrap().parse::<u32>().unwrap(), iter.next().unwrap().parse::<u32>().unwrap());
        assert!(iter.next().is_none());
        ret
    };
    let date = NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(h, 0, 0).unwrap();
    let date: DateTime<FixedOffset> = DateTime::from_naive_utc_and_offset(date, FixedOffset::west_opt(0).unwrap());
    date.timestamp_millis() as u64
}

fn calc_dir_size<P: AsRef<Path>>(size: &mut u64, path: P, pre_computed: &mut HashSet<String>) -> anyhow::Result<()> {
    if path.as_ref().is_file() {
        if !pre_computed.insert(path.as_ref().to_str().unwrap().to_string()) {
            return Ok(());
        }
        *size += path.as_ref().metadata()?.len();
        return Ok(());
    }
    if path.as_ref().is_dir() {
        for file in fs::read_dir(path)? {
            calc_dir_size(size, file.unwrap().path(), pre_computed)?;
        }
        return Ok(());
    }
    unreachable!("Found unknown file type")
}

/// upload asset to github release
/// release_upload_url example: https://uploads.github.com/repos/owner/repo/releases/1234/assets
pub async fn upload_asset_release(
    client: &Octocrab,
    owner: &str,
    repo: &str,
    release_id: &str,
    asset_name: &str,
    label: Option<&str>,
    data: &[u8]) {
    let release_upload_url = format!(
        "https://uploads.github.com/repos/{owner}/{repo}/releases/{release_id}/assets",
        owner = owner,
        repo = repo,
        release_id = release_id
    );
    let mut release_upload_url = url::Url::from_str(&release_upload_url).unwrap();
    {
        let mut query_pairs = release_upload_url.query_pairs_mut();
        query_pairs.append_pair("name", asset_name);
        if let Some(label) = label {
            query_pairs.append_pair("label", label);
        }
    }
    println!("upload_url: {}", release_upload_url);
    println!(
        "file_size: {}. It can take some time to upload. Wait...",
        data.len()
    );
    let request = Builder::new().method(Method::POST).uri(release_upload_url.as_str())
    .header("Content-Length", data.len().to_string())
    .header("Content-Type", "application/octet-stream");
    let request = client.build_request(request, Some(data)).unwrap();
    let _response = client.execute(request).await.unwrap();
}