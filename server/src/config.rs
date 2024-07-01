use std::{collections::{HashMap, HashSet}, fs, io::Read, path::Path, time::Duration};

use bytes::BytesMut;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    RsaPrivateKey,
};
use serde_derive::{Deserialize, Serialize};

use crate::{protocol::RWBytes, Token};

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub periods: Vec<u128>, // these are stored in milli seconds
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub max_frame_size_b: u64,
    pub max_file_size_b: u64,
    // FIXME: make storage config per-token and not global, but keep a global default
    pub storage: Storage,
    // FIXME: add seperate registry for tokens (and don't modify config)
    pub tokens: HashSet<Token>,
}

impl Config {
    const PATH: &'static str = "./nas/config.json";

    pub fn load() -> Self {
        if !Path::new(Self::PATH).exists() {
            fs::write(
                Self::PATH,
                serde_json::to_string_pretty(&Config {
                    port: 28462,
                    tokens: HashSet::new(),
                    periods: vec![
                        Duration::from_days(1).as_millis(),
                        Duration::from_days(30).as_millis(),
                        Duration::from_days(365).as_millis(),
                    ],
                    connect_timeout_ms: 15000,
                    read_timeout_ms: 30000,
                    max_frame_size_b: 1024 * 1024 * 64,
                    max_file_size_b: 1024 * 1024 * 1024 * 8,
                    storage: Storage { method: StorageMethod::LocalDisk, gen_delta: false },
                })
                .unwrap(),
            )
            .unwrap();
        }
        serde_json::from_str(&fs::read_to_string(Self::PATH).unwrap()).unwrap()
    }
}

const RSA_KEY_SIZE_BITS: usize = 4096;

pub struct StorageEncyptionKey {
    pub key: RsaPrivateKey,
}

impl StorageEncyptionKey {

    pub fn load(token_hash: &str) -> Self {
        Self {
            key: load_key(&format!("./nas/instances/{token_hash}/storage.key")),
        }
    }

    pub fn store_passwd(token_hash: &str, pw: &str) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pw.as_bytes());
        let mut key = [0; RSA_KEY_SIZE_BITS / 8];
        hasher.finalize_xof().read(&mut key).unwrap();
        fs::write(&format!("./nas/istances/{token_hash}/storage.key"), &key).unwrap();
    }

}

fn load_key(path: &str) -> RsaPrivateKey {
    if !Path::new(path).exists() {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE_BITS).expect("failed to generate a key");
        fs::write(
            path,
            &priv_key.to_pkcs1_der().unwrap().to_bytes().to_vec(),
        )
        .unwrap();
    }
    RsaPrivateKey::from_pkcs1_der(&fs::read(path).unwrap()).unwrap()
}

pub struct NetworkEncryptionKey {
    pub key: RsaPrivateKey,
}

impl NetworkEncryptionKey {
    pub fn load() -> Self {
        Self {
            key: load_key("./nas/network_priv.key"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Storage {
    pub method: StorageMethod,
    pub gen_delta: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum StorageMethod {
    LocalDisk,
    Github {
        token: String,
        name: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MetaCfg {
    pub last_finished_update: u64,
    pub last_started_update: Option<PartialUpdate>,
    pub pub_key: Vec<u8>,
    pub name: Option<String>,
    pub storage_passwd: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartialUpdate {
    pub start: u64,
    pub finished_files: HashMap<String, u64>,
}

pub struct RegisterCfg {
    pub priv_key: Vec<u8>,
    pub server_pub_key: Vec<u8>,
    pub token: Vec<u8>,
}

impl RegisterCfg {
    pub fn store<P: AsRef<Path>>(self, path: P) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        self.priv_key.write(&mut buf)?;
        self.server_pub_key.write(&mut buf)?;
        self.token.write(&mut buf)?;
        fs::write(path, &buf)?;
        Ok(())
    }
}
