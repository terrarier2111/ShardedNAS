use std::{collections::HashSet, fs, path::Path, time::Duration};

use serde_derive::{Deserialize, Serialize};

use crate::Token;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub tokens: HashSet<Token>,
    pub periods: Vec<u128>, // these are stored in milli seconds
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
}

impl Config {
    const PATH: &str = "./nas/config.json";

    pub fn load() -> Self {
        if !Path::new(Self::PATH).exists() {
            fs::write(
                Self::PATH,
                serde_json::to_string(&Config {
                    port: 28462,
                    tokens: HashSet::new(),
                    periods: vec![Duration::from_days(1).as_millis(), Duration::from_days(30).as_millis(), Duration::from_days(365).as_millis()],
                    connect_timeout_ms: 15000,
                    read_timeout_ms: 30000,
                })
                .unwrap(),
            )
            .unwrap();
        }
        serde_json::from_str(&fs::read_to_string(Self::PATH).unwrap()).unwrap()
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
    pub token: Vec<u8>,
}
