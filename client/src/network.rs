use std::net::{Ipv4Addr, SocketAddr, TcpStream};

pub struct NetworkClient {
    conn: TcpStream,
}

impl NetworkClient {

    pub fn new(addr: &str, port: u16) -> anyhow::Result<Self> {
        // FIXME: use addr
        Ok(Self {
            conn: TcpStream::connect(SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port))?,
        })
    }

}