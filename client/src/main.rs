use std::{fs, sync::Arc};

use config::Config;
use swap_it::SwapIt;

mod packet;
mod protocol;
mod utils;
mod config;
mod network;

pub type Token = Vec<u8>;

fn main() {
    let dir_path = "./nas/";
    fs::create_dir(dir_path).unwrap();
    let cfg = Config::load();
    let client = Arc::new(Client {
        cfg: SwapIt::new(cfg),
    });
    
}

pub struct Client {
    pub cfg: SwapIt<Config>,

}
