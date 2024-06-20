use std::{
    hint, io::Write, net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream}, ops::DerefMut, str::FromStr, sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    }, thread, time::Duration
};

use bytes::BytesMut;
use rand::{thread_rng, RngCore};
use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}, sha2::{Digest, Sha512_256}, Oaep, Pss, RsaPrivateKey, RsaPublicKey};
use swap_it::SwapIt;

use crate::{
    config::{Config, RegisterCfg},
    packet::{self, PacketIn, PacketOut},
    protocol::{RWBytes, PROTOCOL_VERSION},
    utils::{current_time_millis, BasicNonce}, Client,
};

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
        let stream =
            TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(addr)?), port))?;

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
                let millis = { cfg.load().timeout_millis };
                thread::sleep(Duration::from_millis(millis / 2));
                let _ = client2.write_packet(PacketOut::KeepAlive);
            }
        });
        Ok((client, raw_key))
    }

    pub fn read_packet(&self) -> anyhow::Result<PacketIn> {
        packet::read_full_packet(
            self.read_conn.lock().unwrap().deref_mut(),
            self.decryption_key.lock().unwrap().deref_mut(),
        )
    }

    pub fn write_packet_rsa(&self, packet: PacketOut, key: &RsaPublicKey) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        let mut rng = thread_rng();
        // FIXME: use sha3-512 instead
        let encrypted = key.encrypt(&mut rng, Oaep::new::<Sha512_256>(), &buf)?;
        let mut final_buf = BytesMut::new();
        (encrypted.len() as u64).write(&mut final_buf)?;
        final_buf.extend(encrypted);
        self.write_conn.lock().unwrap().write_all(&final_buf)?;
        Ok(())
    }

    // FIXME: disconnect on write_packet failure
    pub fn write_packet(&self, packet: PacketOut) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        self.encryption_key
            .lock()
            .unwrap()
            .seal_in_place_append_tag(Aad::empty(), &mut buf)
            .unwrap();
        let mut final_buf = BytesMut::new();
        (buf.len() as u64).write(&mut final_buf)?;
        final_buf.extend(buf);
        self.write_conn.lock().unwrap().write_all(&final_buf)?;
        Ok(())
    }

    pub fn await_acknowledgement(&self) {
        // TODO: reconsider these constants!
        for _ in 0..10000 {
            if self.acknowledged.load(Ordering::Acquire) {
                self.acknowledged.store(false, Ordering::Release);
                return;
            }
            for _ in 0..10 {
                hint::spin_loop();
            }
        }
        while !self.acknowledged.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
        self.acknowledged.store(false, Ordering::Release);
    }

    pub fn shutdown(&self) -> anyhow::Result<bool> {
        if self.running.compare_exchange(true, false, Ordering::Release, Ordering::Acquire).is_err() {
            return Ok(false);
        }
        self.read_conn.lock().unwrap().shutdown(std::net::Shutdown::Both)?;
        Ok(true)
    }
}

pub fn connect(creds: &RegisterCfg, client: &Client) -> anyhow::Result<Arc<NetworkClient>> {
    'outer: loop {
        match NetworkClient::new(client.cfg.clone()) {
            Ok((conn, key)) => {
                conn.write_packet_rsa(
                    packet::PacketOut::Login {
                        version: PROTOCOL_VERSION,
                        token: creds.token.clone(),
                        key,
                    },
                    &RsaPublicKey::from_pkcs1_der(&creds.server_pub_key).unwrap(),
                )
                .unwrap();
                let packet = conn.read_packet();
                if let PacketIn::ChallengeRequest { challenge } = packet.unwrap() {
                    let mut hasher = Sha512_256::new();
                    hasher.update(&challenge);
                    let hashed = hasher.finalize();
                    let signed = RsaPrivateKey::from_pkcs1_der(&creds.priv_key)
                        .expect("Invalid private key")
                        .sign_with_rng(&mut rand::thread_rng(), Pss::new::<Sha512_256>(), &hashed)
                        .unwrap();
                    conn.write_packet(packet::PacketOut::ChallengeResponse { val: signed })
                        .unwrap();
                    if let Ok(PacketIn::LoginSuccess { max_frame_size }) = conn.read_packet() {
                        conn.max_frame_size.store(max_frame_size, Ordering::Release);
                        client.println("Successfully logged in");
                    } else {
                        client.println("Authentication failed");
                        continue;
                    }
                } else {
                    client.println("Received weird packet in login sequence");
                    continue;
                }

                let conn2 = conn.clone();
                thread::spawn(move || {
                    let conn = conn2;
                    while conn.running.load(Ordering::Acquire) {
                        let packet = match conn.read_packet() {
                            Ok(packet) => packet,
                            Err(_) => break,
                        };
                        match packet {
                            PacketIn::ChallengeRequest { .. } => unreachable!(),
                            PacketIn::LoginSuccess { .. } => unreachable!(),
                            PacketIn::KeepAlive => {
                                conn
                                    .last_keep_alive
                                    .store(current_time_millis() as u64, Ordering::Release);
                            }
                            PacketIn::FrameRequest => {
                                conn.acknowledged.store(true, Ordering::Release);
                            }
                        }
                    }
                });

                break 'outer Ok(conn);
            }
            Err(_) => {
                client.println("Connecting failed, retrying in 10 seconds.");
                thread::sleep(Duration::from_secs(10));
            }
        }
    }
}
