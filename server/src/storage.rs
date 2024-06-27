use std::{fs::{self, OpenOptions}, io::Write, path::Path, str::FromStr};

use chrono::{DateTime, Datelike, Timelike, Utc};
use http::request::Builder;
use octocrab::{repos::releases::MakeLatest, Octocrab};
use reqwest::Method;

use crate::{config::Storage, utils::remove_path};

impl Storage {

    pub async fn save_file(&self, update_start: DateTime<Utc>, token_hash: &str, file_name: &str, content: Option<&[u8]>, remaining_bytes: u64) -> anyhow::Result<()> {
        match &self.method {
            crate::config::StorageMethod::LocalDisk => {
                if let Some(parent) = Path::new(file_name).parent() {
                    fs::create_dir_all(format!(
                        "./nas/instances/{}/storage/{}",
                        token_hash,
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
                                &format!("./nas/instances/{}/storage/{}", token_hash, file_name),
                            )?;
                            // clean up tmp file
                            fs::remove_file(&tmp_path)?;
                        }
                    }
                    None => {
                        remove_path(&format!(
                            "./nas/instances/{}/storage/{}",
                            token_hash, file_name
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