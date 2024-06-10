use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::DerefMut,
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    }, time::Duration,
};

use bytes::BytesMut;
use rand::RngCore;
use rsa::{pkcs1::DecodeRsaPublicKey, sha2::Sha256, Pss, RsaPublicKey};
use swap_it::SwapIt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use crate::{
    binary_to_str, config::MetaCfg, packet::{read_full_packet, write_full_packet, PacketIn, PacketOut, PushResponse}, protocol::{RWBytes, PROTOCOL_VERSION}, utils::current_time_millis, Server, Token
};

pub struct NetworkServer {
    server: Mutex<TcpListener>,
    pub clients: Mutex<Vec<Connection>>,
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
                        server.println(&format!("error listening for connections {err}"));
                    }
                }
            }
        });
    }
}

const IDLE_TRANSMISSION: usize = usize::MAX;

pub struct Connection {
    pub id: Token,
    cfg: SwapIt<MetaCfg>,
    conn: Arc<Mutex<TcpStream>>,
    pub addr: SocketAddr,
    curr_trans_idx: AtomicUsize,
    last_keep_alive: AtomicU64,
}

impl Connection {
    async fn handle_packets(self: Arc<Self>) {
        let conn = self.conn.clone();
        let id = self.id.clone();
        let id_str = binary_to_str(&id);
        tokio::spawn(async move {
            // FIXME: terminate on server shutdown
            loop {
                let packet = read_full_packet(conn.lock().await.deref_mut())
                    .await
                    .unwrap();
                match packet {
                    PacketIn::Login { .. } => unreachable!("unexpected login packet"),
                    PacketIn::PushResponse { response } => match response {
                        PushResponse::CompletedTransmission => {
                            let mut cfg = self.cfg.load().clone();
                            cfg.last_updates[self.curr_trans_idx.load(Ordering::Acquire)] =
                                current_time_millis();
                            fs::write(format!("./nas/instances/{}/meta.json", &id_str), serde_json::to_string(&cfg).unwrap().as_bytes()).unwrap();
                        }
                        // FIXME: handle other cases
                        _ => {}
                    },
                    PacketIn::PushRequest => todo!(),
                    PacketIn::DeliverFrame { file_name, content } => {
                        if file_name.contains("..") || file_name.starts_with("/") {
                            // FIXME: kill connection, as it attempted to perform bad file actions
                            return;
                        }
                        if let Some(parent) = Path::new(&file_name).parent() {
                            fs::create_dir_all(format!(
                                "./nas/instances/{}/storage/{:?}",
                                &id_str, parent
                            ))
                            .unwrap();
                        }
                        let tmp_path = format!(
                            "./nas/tmp/{}_{}",
                            &id_str,
                            Path::new(&file_name)
                                .file_name()
                                .map(|name| name.to_str().unwrap())
                                .unwrap_or(file_name.as_str())
                        );
                        fs::write(&tmp_path, content).unwrap();
                        // replace original file
                        fs::copy(&tmp_path, &file_name).unwrap();
                        // clean up tmp file
                        fs::remove_file(&tmp_path).unwrap();

                        write_full_packet(conn.lock().await.deref_mut(), PacketOut::RequestFrame).await.unwrap();
                    }
                    PacketIn::ChallengeResponse { .. } => unreachable!("unexpected login challenge packet"),
                    PacketIn::KeepAlive => {
                        self.last_keep_alive.store(current_time_millis() as u64, Ordering::Release);
                    },
                }
            }
        });
    }
}

struct PendingConn {
    server: Arc<Server>,
    conn: TcpStream,
    addr: SocketAddr,
}

impl PendingConn {
    async fn await_login(mut self) {
        tokio::spawn(async move {
            let login = match tokio::time::timeout(Duration::from_millis(self.server.cfg.load().connect_timeout_ms), read_full_packet(&mut self.conn)).await {
                Ok(packet) => packet.unwrap(),
                // a timeout occoured
                Err(_) => return,
            };
            if let PacketIn::Login { token, version } = login {
                if version != PROTOCOL_VERSION {
                    self.server.println(&format!("A client tried to connect with an incompatible version ({})", version));
                    return;
                }
                if !self.server.is_trusted(&token) {
                    self.server
                        .println("Client with untrusted token tried logging in");
                    // FIXME: block ip for some time (a couple seconds) to prevent guessing a correct token through brute force
                    return;
                }
                let token_str = binary_to_str(&token);
                let cfg: MetaCfg = serde_json::from_str(
                    &fs::read_to_string(format!("./nas/instances/{}/meta.json", &token_str))
                        .unwrap(),
                )
                .unwrap();
                let mut challenge = [0; 256];
                rand::thread_rng().fill_bytes(&mut challenge);

                write_full_packet(&mut self.conn, PacketOut::ChallengeRequest { challenge: challenge.to_vec() }).await.unwrap();
                
                if let PacketIn::ChallengeResponse { val } = read_full_packet(&mut self.conn).await.unwrap() {
                    let pub_key = RsaPublicKey::from_pkcs1_der(&cfg.pub_key).unwrap();
                    if pub_key.verify(Pss::new::<Sha256>(), &challenge, &val).is_err() {
                        // FIXME: block ip as it tried to immitate the token holder
                        return;
                    }
                } else {
                    self.server
                    .println("Unexpected packet received during login");
                return;
                }

                self.server.network.clients.lock().await.push(Connection {
                    id: token,
                    conn: Arc::new(Mutex::new(self.conn)),
                    addr: self.addr,
                    cfg: SwapIt::new(cfg),
                    curr_trans_idx: AtomicUsize::new(IDLE_TRANSMISSION),
                    last_keep_alive: AtomicU64::new(current_time_millis() as u64),
                });
                self.server
                    .println(&format!("Client {} connected", token_str));
            } else {
                self.server
                    .println("Unexpected packet received during login");
                return;
            }
        });
    }
}
