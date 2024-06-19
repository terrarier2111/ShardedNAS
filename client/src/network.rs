use std::{io::Write, net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream}, ops::DerefMut, str::FromStr, sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex}, thread, time::Duration};

use bytes::BytesMut;
use rand::thread_rng;
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey};
use swap_it::SwapIt;

use crate::{config::Config, packet::{self, PacketIn, PacketOut}, protocol::RWBytes, utils::current_time_millis};

pub struct NetworkClient {
    read_conn: Mutex<TcpStream>,
    write_conn: Mutex<TcpStream>,
    pub last_keep_alive: AtomicU64,
    pub running: AtomicBool,
    pub acknowledged: AtomicBool,
    pub max_frame_size: AtomicU64,
    priv_key: RsaPrivateKey,
    pub_server_key: RsaPublicKey,
}

impl NetworkClient {

    pub fn new(cfg: Arc<SwapIt<Config>>, pub_server_key: Vec<u8>, priv_key: Vec<u8>) -> anyhow::Result<Arc<Self>> {
        let t_cfg = cfg.load();
        let addr = t_cfg.dst.as_str();
        let port = t_cfg.port;
        let stream = TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(addr)?), port))?;
        let client = Arc::new(Self {
            read_conn: Mutex::new(stream.try_clone()?),
            write_conn: Mutex::new(stream),
            last_keep_alive: AtomicU64::new(current_time_millis() as u64),
            acknowledged: AtomicBool::new(false),
            running: AtomicBool::new(true),
            max_frame_size: AtomicU64::new(u64::MAX),
            priv_key: RsaPrivateKey::from_pkcs1_der(&priv_key).unwrap(),
            pub_server_key: RsaPublicKey::from_pkcs1_der(&pub_server_key).unwrap(),
        });
        let client2 = client.clone();
        thread::spawn(move || {
            while client2.running.load(Ordering::Acquire) {
                let millis = {
                    cfg.load().timeout_millis
                };
                thread::sleep(Duration::from_millis(millis / 2));
                client2.write_packet(PacketOut::KeepAlive).unwrap();
            }
        });
        Ok(client)
    }

    pub fn read_packet(&self) -> anyhow::Result<PacketIn> {
        packet::read_full_packet(self.read_conn.lock().unwrap().deref_mut(), &self.priv_key)
    }

    pub fn write_packet(&self, packet: PacketOut) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        let mut rng = thread_rng();
        let encrypted = self.pub_server_key.encrypt(&mut rng, Oaep::new::<Sha256>(), &buf)?;
        let mut final_buf = BytesMut::new();
        (buf.len() as u64).write(&mut final_buf)?;
        final_buf.extend(encrypted);
        self.write_conn.lock().unwrap().write_all(&final_buf)?;
        Ok(())
    }

}