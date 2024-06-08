use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::DerefMut,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use bytes::BytesMut;
use swap_it::SwapIt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use crate::{
    config::MetaCfg,
    packet::{read_full_packet, PacketIn, PacketOut, PushResponse},
    protocol::RWBytes,
    utils::current_time_millis,
    Server, Token,
};

pub struct NetworkServer {
    server: Mutex<TcpListener>,
    clients: Mutex<Vec<Connection>>,
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

struct Connection {
    id: Token,
    cfg: SwapIt<MetaCfg>,
    conn: Arc<Mutex<TcpStream>>,
    addr: SocketAddr,
    curr_trans_idx: AtomicUsize,
}

impl Connection {
    async fn send_packet(&self, packet: PacketOut) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        packet.write(&mut buf)?;
        let mut final_buf = BytesMut::new();
        (buf.len() as u64).write(&mut final_buf)?;
        final_buf.extend_from_slice(&buf);
        self.conn.lock().await.write_all(&final_buf).await.unwrap();
        Ok(())
    }

    async fn handle_packets(self: Arc<Self>) {
        let conn = self.conn.clone();
        let id = self.id.clone();
        let id_str = {
            let mut res = String::new();
            for id in id.iter() {
                res.push_str(id.to_string().as_str());
            }
            res
        };
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
                            // FIXME: write cfg back to disk
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

                        self.send_packet(PacketOut::RequestFrame).await.unwrap();
                    }
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
            let login = read_full_packet(&mut self.conn).await.unwrap();
            if let PacketIn::Login { token } = login {
                if !self.server.is_trusted(&token) {
                    self.server
                        .println("Client with untrusted token tried logging in");
                    // FIXME: block ip for some time (a couple seconds) to prevent guessing a correct token through brute force
                    return;
                }
                let token_str = {
                    let mut res = String::new();
                    for token in token.iter() {
                        res.push_str(token.to_string().as_str());
                    }
                    res
                };
                let cfg = serde_json::from_str(
                    &fs::read_to_string(format!("./nas/instances/{}/meta.json", &token_str))
                        .unwrap(),
                )
                .unwrap();
                self.server.network.clients.lock().await.push(Connection {
                    id: token,
                    conn: Arc::new(Mutex::new(self.conn)),
                    addr: self.addr,
                    cfg: SwapIt::new(cfg),
                    curr_trans_idx: AtomicUsize::new(IDLE_TRANSMISSION),
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
