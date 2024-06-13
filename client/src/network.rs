use std::{io::Write, net::{Ipv4Addr, SocketAddr, TcpStream}, ops::DerefMut, str::FromStr, sync::Mutex};

use bytes::BytesMut;

use crate::{packet::{self, PacketIn, PacketOut}, protocol::RWBytes};

pub struct NetworkClient {
    read_conn: Mutex<TcpStream>,
    write_conn: Mutex<TcpStream>,
}

impl NetworkClient {

    pub fn new(addr: &str, port: u16) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::from_str(addr)?), port))?;
        Ok(Self {
            read_conn: Mutex::new(stream.try_clone()?),
            write_conn: Mutex::new(stream),
        })
    }

    pub fn read_packet(&self) -> anyhow::Result<PacketIn> {
        packet::read_full_packet(self.read_conn.lock().unwrap().deref_mut())
    }

    pub fn write_packet(&self, packet: PacketOut) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        let mut final_buf = BytesMut::new();
        (buf.len() as u64).write(&mut final_buf)?;
        final_buf.extend(buf);
        self.write_conn.lock().unwrap().write_all(&final_buf)?;
        Ok(())
    }

}