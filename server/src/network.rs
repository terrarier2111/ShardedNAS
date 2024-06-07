use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::net::{TcpListener, TcpStream};

pub struct Server {
    server: TcpListener,
    clients: Vec<TcpStream>,
}

impl Server {

    pub async fn new(port: u16) -> Self {
        Self {
            server: TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))).await.unwrap(),
            clients: vec![],
        }
    }

    pub async fn listen_login(&self) {
        
    }

    async fn listen_packets(&self) {

    }

}