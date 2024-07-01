use std::{
    collections::HashMap, fs, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, ops::DerefMut, sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    }, time::Duration
};

use chrono::{DateTime, Utc};
use rand::RngCore;
use ring::aead::{BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    sha2::{Digest, Sha512_256},
    Pss, RsaPublicKey,
};
use swap_it::SwapIt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use crate::{
    binary_to_hash, config::{MetaCfg, PartialUpdate, StorageEncyptionKey}, packet::{read_full_packet, read_full_packet_rsa, write_full_packet, PacketIn, PacketOut}, protocol::PROTOCOL_VERSION, utils::{current_time_millis, BasicNonce}, Server, Token
};

pub struct NetworkServer {
    server: Mutex<TcpListener>,
    pub clients: Mutex<Vec<Arc<Connection>>>,
}

impl NetworkServer {
    pub async fn new(port: u16) -> Self {
        Self {
            server: Mutex::new(
                TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
                    .await
                    .unwrap(),
            ),
            clients: Mutex::new(vec![]),
        }
    }

    pub async fn listen_login(&self, server: Arc<Server>) {
        tokio::spawn(async move {
            while server.is_running() {
                match server.network.server.lock().await.accept().await {
                    Ok((client, addr)) => {
                        PendingConn {
                            server: server.clone(),
                            conn: client,
                            addr,
                        }
                        .await_login()
                        .await;
                    }
                    Err(err) => {
                        server.println(&format!("Error listening for connections {err}"));
                    }
                }
            }
        });
    }
}

pub struct Connection {
    pub id: Token,
    cfg: SwapIt<MetaCfg>,
    storage_key: Option<StorageEncyptionKey>,
    conn: Arc<Mutex<TcpStream>>,
    pub addr: SocketAddr,
    encrypt_key: Mutex<SealingKey<BasicNonce>>,
    last_keep_alive: AtomicU64,
    shutdown: AtomicBool,
}

impl Connection {
    async fn handle_packets(
        self: Arc<Self>,
        server: Arc<Server>,
        decrypt_key: OpeningKey<BasicNonce>,
    ) {
        let conn = self.conn.clone();
        let id = self.id.clone();
        let hash = binary_to_hash(&id);
        tokio::spawn(async move {
            let mut key = decrypt_key;
            // FIXME: terminate on server shutdown
            while server.is_running() && self.is_running() {
                let packet = match read_full_packet(conn.lock().await.deref_mut(), &mut key).await {
                    Ok(packet) => packet,
                    Err(_) => {
                        let _ = self.shutdown(&server).await;
                        break;
                    }
                };
                match packet {
                    PacketIn::Login { .. } => unreachable!("unexpected login packet"),
                    PacketIn::ChallengeResponse { .. } => unreachable!("unexpected login challenge packet"),
                    PacketIn::KeepAlive => {
                        self.last_keep_alive
                            .store(current_time_millis() as u64, Ordering::Release);
                        // ignore errors for now
                        let _ = self.write_packet(PacketOut::KeepAlive, &server).await;
                    }
                    PacketIn::BackupRequest => {
                        // FIXME: determine whether we are currently under load and wait until there is less

                        // request first frame,
                        // ignore errors for now
                        let _ = self.write_packet(PacketOut::FrameRequest, &server).await;
                        let mut meta = self.cfg.load().clone();
                        server.println(&format!(
                            "Client \"{}\" started backup...",
                            meta.name.as_ref().unwrap_or(&hash)
                        ));
                        meta.last_started_update = Some(PartialUpdate {
                            start: current_time_millis() as u64,
                            finished_files: HashMap::new(),
                        });
                        save_meta(&hash, &meta).unwrap();
                    }
                    PacketIn::DeliverFrame {
                        file_name,
                        file_hash,
                        content,
                        remaining_bytes,
                    } => {
                        if file_name.contains("..") {
                            // FIXME: kill connection, as it attempted to perform bad file actions
                            return;
                        }
                        let full_name = file_name;
                        let file_name = {
                            let start_cnt = 'outer: {
                                for i in 0..full_name.len() {
                                    if full_name.chars().skip(i).next() != Some('/') {
                                        break 'outer i;
                                    }
                                }
                                full_name.len()
                            };
                            (&full_name[start_cnt..]).to_string()
                        };
                        let mut meta = self.cfg.load().clone();
                        let time = if let Some(partial_update) = meta.last_started_update.as_ref() {
                            if partial_update.finished_files.get(&full_name).cloned() == Some(file_hash) {
                                // the hashes match up, there is no new info
                                continue;
                            }
                            DateTime::from_timestamp_millis(partial_update.start as i64).unwrap()
                        } else {
                            Utc::now()
                        };
                        server.cfg.load().storage.save_file(self.storage_key.as_ref(), time, &hash, &file_name, content.as_deref(), remaining_bytes).await.unwrap();
                        meta.last_started_update.as_mut().unwrap().finished_files.insert(full_name, file_hash);
                        save_meta(&hash, &meta).unwrap();

                        // ignore errors for now
                        let _ = self.write_packet(PacketOut::FrameRequest, &server).await;
                    }
                    PacketIn::FinishedBackup => {
                        let mut cfg = self.cfg.load().clone();
                        cfg.last_finished_update = cfg.last_started_update.as_ref().unwrap().start;
                        cfg.last_started_update = None;
                        save_meta(&hash, &cfg).unwrap();
                        server.println(&format!(
                            "Client \"{}\" finished backup",
                            cfg.name.as_ref().unwrap_or(&hash)
                        ));
                        // there's nothing to do anymore, so cut the connection
                        let _ = self.shutdown(&server).await;
                    }
                }
            }
            let _ = self.conn.lock().await.shutdown().await;
        });
    }

    pub async fn shutdown(&self, server: &Arc<Server>) -> anyhow::Result<bool> {
        if self
            .shutdown
            .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
            .is_err()
        {
            return Ok(false);
        }
        if let Some(name) = self.cfg.load().name.as_ref() {
            server.println(&format!("Client \"{}\" disconnected", name));
        } else {
            server.println(&format!(
                "Client \"{}\" disconnected",
                binary_to_hash(&self.id)
            ));
        }
        self.conn.lock().await.shutdown().await?;
        Ok(true)
    }

    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
    }

    async fn write_packet(&self, packet: PacketOut, server: &Arc<Server>) -> anyhow::Result<()> {
        match write_full_packet(
            self.conn.lock().await.deref_mut(),
            packet,
            self.encrypt_key.lock().await.deref_mut(),
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                // the error we deliver is more important than the disconnect error
                let _ = self.shutdown(server).await;
                Err(error)
            }
        }
    }
}

fn save_meta(hash: &str, meta: &MetaCfg) -> anyhow::Result<()> {
    fs::write(
        format!("./nas/instances/{}/meta.json", hash),
        serde_json::to_string(meta)?.as_bytes(),
    )?;
    Ok(())
}

struct PendingConn {
    server: Arc<Server>,
    conn: TcpStream,
    addr: SocketAddr,
}

impl PendingConn {
    async fn await_login(mut self) {
        self.conn
            .set_nodelay(true)
            .expect("Failure setting no_delay");
        tokio::spawn(async move {
            let login = match tokio::time::timeout(
                Duration::from_millis(self.server.cfg.load().connect_timeout_ms),
                read_full_packet_rsa(&mut self.conn, &self.server.key.key),
            )
            .await
            {
                Ok(Ok(packet)) => packet,
                // a timeout or an error occoured
                Err(_) | Ok(Err(_)) => return,
            };
            if let PacketIn::Login {
                version,
                token,
                key,
            } = login
            {
                if version != PROTOCOL_VERSION {
                    self.server.println(&format!(
                        "A client tried to connect with an incompatible version ({})",
                        version
                    ));
                    return;
                }
                if !self.server.is_trusted(&token) {
                    self.server
                        .println("Client with untrusted token tried logging in");
                    // FIXME: block ip for some time (a couple seconds) to prevent guessing a correct token through brute force
                    return;
                }
                let token_str = binary_to_hash(&token);
                let cfg: MetaCfg =
                    match fs::read_to_string(format!("./nas/instances/{}/meta.json", &token_str)) {
                        Ok(data) => match serde_json::from_str(&data) {
                            Ok(cfg) => cfg,
                            Err(_) => {
                                self.server.println(&format!(
                                    "Unreadable metadata for token {}",
                                    token_str
                                ));
                                return;
                            }
                        },
                        Err(_) => {
                            // unknown token provided
                            return;
                        }
                    };
                let mut encrypt_key = match UnboundKey::new(&AES_256_GCM, &key) {
                    Ok(key) => SealingKey::new(key, BasicNonce::new()),
                    Err(_) => return,
                };
                let mut decrypt_key = OpeningKey::new(
                    UnboundKey::new(&AES_256_GCM, &key).unwrap(),
                    BasicNonce::new(),
                );

                let mut challenge = [0; 256];
                rand::thread_rng().fill_bytes(&mut challenge);

                if let Err(_) = write_full_packet(
                    &mut self.conn,
                    PacketOut::ChallengeRequest {
                        challenge: challenge.to_vec(),
                    },
                    &mut encrypt_key,
                )
                .await
                {
                    return;
                }

                let packet = match read_full_packet(&mut self.conn, &mut decrypt_key).await {
                    Ok(packet) => packet,
                    Err(_) => {
                        // couldn't read data from connection
                        return;
                    }
                };

                if let PacketIn::ChallengeResponse { val } = packet {
                    let pub_key = RsaPublicKey::from_pkcs1_der(&cfg.pub_key).unwrap();
                    let mut hasher = Sha512_256::new();
                    hasher.update(&challenge);
                    let hash = hasher.finalize();
                    if pub_key
                        .verify(Pss::new::<Sha512_256>(), &hash, &val)
                        .is_err()
                    {
                        self.server.println("Failed challenge during login");
                        // FIXME: block ip as it tried to immitate the token holder
                        return;
                    }
                } else {
                    self.server
                        .println("Unexpected packet received during login");
                    return;
                }

                if let Err(_) = write_full_packet(
                    &mut self.conn,
                    PacketOut::LoginSuccess {
                        max_frame_size: self.server.cfg.load().connect_timeout_ms,
                    },
                    &mut encrypt_key,
                )
                .await
                {
                    self.server.println(&format!(
                        "The client \"{}\" immediately disconnected",
                        cfg.name.as_ref().unwrap_or(&token_str)
                    ));
                    return;
                }

                let conn = Arc::new(Connection {
                    id: token,
                    conn: Arc::new(Mutex::new(self.conn)),
                    addr: self.addr,
                    storage_key: if cfg.storage_passwd.is_none() { Some(StorageEncyptionKey::load()) } else { None },
                    cfg: SwapIt::new(cfg),
                    last_keep_alive: AtomicU64::new(current_time_millis() as u64),
                    shutdown: AtomicBool::new(false),
                    encrypt_key: Mutex::new(encrypt_key),
                });
                conn.clone()
                    .handle_packets(self.server.clone(), decrypt_key)
                    .await;
                self.server.network.clients.lock().await.push(conn.clone());
                self.server.println(&format!(
                    "Client \"{}\" connected",
                    conn.cfg.load().name.as_ref().unwrap_or(&token_str)
                ));
            } else {
                self.server
                    .println("Unexpected packet received during login");
                return;
            }
        });
    }
}
