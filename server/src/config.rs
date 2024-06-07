use std::{fs, path::Path};

use serde_derive::{Deserialize, Serialize};

use crate::Token;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub tokens: Vec<Token>,
    pub periods: Vec<usize>, // these are stored in milli seconds
}

impl Config {

    const PATH: &str = "./nas/config.json";

    pub fn load() -> Self {
        if !Path::new(Self::PATH).exists() {
            fs::write(Self::PATH, serde_json::to_string(&Config {
                port: 28462,
                tokens: vec![],
                periods: vec![],
            }).unwrap()).unwrap();
        }
        serde_json::from_str(&fs::read_to_string(Self::PATH).unwrap()).unwrap()
    }

}

pub struct MetaCfg {
    pub id: Token,
    pub last_update: usize,
}