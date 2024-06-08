use std::{collections::HashSet, fs, path::Path};

use serde_derive::{Deserialize, Serialize};

use crate::Token;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub tokens: HashSet<Token>,
    pub periods: Vec<u128>, // these are stored in milli seconds
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
                    periods: vec![],
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
}
