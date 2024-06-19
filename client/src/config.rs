use std::{collections::HashMap, fs, path::Path};

use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub dst: String,
    pub port: u16,
    pub backup_locations: Vec<String>,
    pub timeout_millis: u64,
}

impl Config {

    const CFG_PATH: &str = "./nas/config.json";

    pub fn load() -> Self {
        if !Path::new(Self::CFG_PATH).exists() {
            fs::write(Self::CFG_PATH, serde_json::to_string_pretty(&Self { dst: "127.0.0.1".to_string(), port: 28462, backup_locations: vec![], timeout_millis: 30000 }).unwrap()).unwrap();
        }
        serde_json::from_str(&fs::read_to_string(Self::CFG_PATH).unwrap()).unwrap()
    }

}

#[derive(Serialize, Deserialize)]
pub struct Meta {
    /// fingerprints of files that were already sent to the backup server
    pub fingerprints: HashMap<String, u64>,
    pub last_update: u128,
}

impl Meta {

    const META_PATH: &str = "./nas/meta.json";

    pub fn load() -> Self {
        if !Path::new(Self::META_PATH).exists() {
            Self::store(&Self {
                fingerprints: HashMap::new(),
                last_update: 0,
            });
        }
        serde_json::from_str(&fs::read_to_string(Self::META_PATH).unwrap()).unwrap()
    }

    pub fn store(&self) {
        fs::write(Self::META_PATH, serde_json::to_string_pretty(self).unwrap()).unwrap();
    }

}

#[derive(Serialize, Deserialize)]
pub struct RegisterCfg {
    pub priv_key: Vec<u8>,
    pub server_pub_key: Vec<u8>,
    pub token: Vec<u8>,
}