use std::{collections::HashMap, fs, path::Path};

use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub dst: String,
    pub port: u16,
}

impl Config {

    const CFG_PATH: &str = "./nas/meta.json";

    pub fn load() -> Self {
        if !Path::new(Self::CFG_PATH).exists() {
            fs::write(Self::CFG_PATH, serde_json::to_string(&Self { dst: "127.0.0.1".to_string(), port: 28462 }).unwrap()).unwrap();
        }
        serde_json::from_str(&fs::read_to_string("./nas/meta.json").unwrap()).unwrap()
    }

}

#[derive(Serialize, Deserialize)]
pub struct Meta {
    /// fingerprints of files that were already sent to the backup server
    pub fingerprints: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterCfg {
    pub priv_key: Vec<u8>,
    pub token: Vec<u8>,
}