use std::{collections::HashSet, fs, path::Path, time::Duration};

use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    RsaPrivateKey,
};
use serde_derive::{Deserialize, Serialize};

use crate::Token;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub tokens: HashSet<Token>,
    pub periods: Vec<u128>, // these are stored in milli seconds
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub max_frame_size_b: u64,
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
                })
                .unwrap(),
            )
            .unwrap();
        }
        serde_json::from_str(&fs::read_to_string(Self::PATH).unwrap()).unwrap()
    }
}

pub struct EncryptionKey {
    pub key: RsaPrivateKey,
}

impl EncryptionKey {
    const PATH: &'static str = "./nas/private.key";

    pub fn load() -> Self {
        if !Path::new(Self::PATH).exists() {
            let mut rng = rand::thread_rng();
            let bits = 4096;
            let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
            fs::write(
                Self::PATH,
                &priv_key.to_pkcs1_der().unwrap().to_bytes().to_vec(),
            )
            .unwrap();
        }
        Self {
            key: RsaPrivateKey::from_pkcs1_der(&fs::read(Self::PATH).unwrap()).unwrap(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MetaCfg {
    pub last_updates: Vec<u128>,
    pub pub_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterCfg {
    pub priv_key: Vec<u8>,
    pub server_pub_key: Vec<u8>,
    pub token: Vec<u8>,
}
