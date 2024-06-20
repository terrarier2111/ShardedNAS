use std::{io::Write, net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream}, ops::DerefMut, str::FromStr, sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex}, thread, time::Duration};

use bytes::BytesMut;
use rand::{thread_rng, RngCore};
use ring::{aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM}, rsa::PublicKey};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey};
use swap_it::SwapIt;

use crate::{config::Config, packet::{self, PacketIn, PacketOut}, protocol::RWBytes, utils::{current_time_millis, BasicNonce}};

pub struct NetworkClient {
    read_conn: Mutex<TcpStream>,
    write_conn: Mutex<TcpStream>,
    pub last_keep_alive: AtomicU64,
    pub running: AtomicBool,
    pub acknowledged: AtomicBool,
    pub max_frame_size: AtomicU64,
    encryption_key: Mutex<SealingKey<BasicNonce>>,
    decryption_key: Mutex<OpeningKey<BasicNonce>>,
}

impl NetworkClient {

    pub fn new(cfg: Arc<SwapIt<Config>>) -> anyhow::Result<(Arc<Self>, [u8; 32])> {
        let t_cfg = cfg.load();
        let addr = t_cfg.dst.as_str();
        let port = t_cfg.port;
        let stream = TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(addr)?), port))?;

        let mut raw_key = [0; 32];
        thread_rng().fill_bytes(&mut raw_key);
        let enc_key = UnboundKey::new(&AES_256_GCM, &raw_key).unwrap();
        let dec_key = UnboundKey::new(&AES_256_GCM, &raw_key).unwrap();

        let client = Arc::new(Self {
            read_conn: Mutex::new(stream.try_clone()?),
            write_conn: Mutex::new(stream),
            last_keep_alive: AtomicU64::new(current_time_millis() as u64),
            acknowledged: AtomicBool::new(false),
            running: AtomicBool::new(true),
            max_frame_size: AtomicU64::new(u64::MAX),
            encryption_key: Mutex::new(SealingKey::new(enc_key, BasicNonce::new())),
            decryption_key: Mutex::new(OpeningKey::new(dec_key, BasicNonce::new())),
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
        Ok((client, raw_key))
    }

    pub fn read_packet(&self) -> anyhow::Result<PacketIn> {
        packet::read_full_packet(self.read_conn.lock().unwrap().deref_mut(), self.decryption_key.lock().unwrap().deref_mut())
    }

    pub fn write_packet_rsa(&self, packet: PacketOut, key: &RsaPublicKey) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        let mut rng = thread_rng();
        let encrypted = key.encrypt(&mut rng, Oaep::new::<Sha256>(), &buf)?;
        let mut final_buf = BytesMut::new();
        (encrypted.len() as u64).write(&mut final_buf)?;
        final_buf.extend(encrypted);
        self.write_conn.lock().unwrap().write_all(&final_buf)?;
        Ok(())
    }

    pub fn write_packet(&self, packet: PacketOut) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        self.encryption_key.lock().unwrap().seal_in_place_append_tag(Aad::empty(), &mut buf).unwrap();
        let mut final_buf = BytesMut::new();
        (buf.len() as u64).write(&mut final_buf)?;
        final_buf.extend(buf);
        self.write_conn.lock().unwrap().write_all(&final_buf)?;
        Ok(())
    }

}