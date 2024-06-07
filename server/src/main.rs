use std::fs;

use config::Config;

mod protocol;
mod packet;
mod network;
mod config;

pub type Token = Vec<u8>;

#[tokio::main]
async fn main() {
    fs::create_dir_all("./nas").unwrap();
    let cfg = Config::load();
    
}
