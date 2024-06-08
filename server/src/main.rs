use std::{fs, sync::{atomic::{AtomicBool, Ordering}, Arc}, thread, time::Duration};

use config::Config;
use network::NetworkServer;
use swap_it::SwapIt;

mod protocol;
mod packet;
mod network;
mod config;
mod utils;

pub type Token = Vec<u8>;

#[tokio::main]
async fn main() {
    fs::create_dir_all("./nas").unwrap();
    let cfg = Config::load();
    let server = Arc::new(Server { running: AtomicBool::new(false), network: NetworkServer::new(cfg.port).await, cfg: SwapIt::new(cfg) });
    server.network.listen_login(server.clone()).await;
    while server.is_running() {
        thread::sleep(Duration::from_millis(50));
    }
    // give the rest of the server time to properly shut down
    thread::sleep(Duration::from_millis(50));
}

pub struct Server {
    running: AtomicBool,
    cfg: SwapIt<Config>,
    network: NetworkServer,
}

impl Server {

    pub fn is_trusted(&self, token: &Token) -> bool {
        self.cfg.load().tokens.contains(token)
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
    }

}