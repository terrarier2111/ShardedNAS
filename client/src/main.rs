#![feature(duration_constructors)]

use std::{collections::HashMap, fs::{self, File, OpenOptions}, hint, io::{Read, Write}, ops::Deref, path::Path, sync::{atomic::{AtomicBool, Ordering}, Arc}, thread, time::Duration};

use clitty::{core::{CommandBuilder, CommandImpl}, ui::{CLIBuilder, CmdLineInterface, PrintFallback}};
use config::{Config, Meta, RegisterCfg};
use network::NetworkClient;
use packet::PacketIn;
use protocol::PROTOCOL_VERSION;
use rsa::{pkcs1::DecodeRsaPrivateKey, sha2::{digest::core_api::VariableOutputCore, Digest, Sha256, Sha512VarCore}, Pss, RsaPrivateKey};
use swap_it::SwapIt;
use utils::current_time_millis;

mod packet;
mod protocol;
mod utils;
mod config;
mod network;

pub type Token = Vec<u8>;

fn main() {
    let window = CLIBuilder::new()
        .prompt("SharedNAS: ".to_string())
        .command(CommandBuilder::new("help", CmdHelp))
        .fallback(Box::new(PrintFallback::new("This command doesn't exist".to_string())))
        .build();
    let cli = Arc::new(CmdLineInterface::new(window));
    let dir_path = "./nas/";
    fs::create_dir_all(dir_path).unwrap();
    if !Path::new("./nas/credentials.json").exists() {
        cli.println("Got no credentials, shutting down in 10 seconds...");
        thread::sleep(Duration::from_secs(10));
        return;
    }
    let creds: RegisterCfg = serde_json::from_str(&fs::read_to_string("./nas/credentials.json").unwrap()).unwrap();
    let cfg = Arc::new(SwapIt::new(Config::load()));
    // FIXME: we only need a network client if the last backup is too old
    let conn = 'outer: loop {
        match NetworkClient::new(cfg.clone()) {
            Ok(conn) => {
                conn.write_packet(packet::PacketOut::Login { token: creds.token.clone(), version: PROTOCOL_VERSION, }).unwrap();
                let packet = conn.read_packet();
                if let PacketIn::ChallengeRequest { challenge } = packet.unwrap() {
                    let mut hasher = Sha256::new();
                    hasher.update(&challenge);
                    let hashed = hasher.finalize();
                    let signed = RsaPrivateKey::from_pkcs1_der(&creds.priv_key).expect("Invalid private key").sign_with_rng(&mut rand::thread_rng(), Pss::new::<Sha256>(), &hashed).unwrap();
                    conn.write_packet(packet::PacketOut::ChallengeResponse { val: signed }).unwrap();
                    if let Ok(PacketIn::LoginSuccess { max_frame_size }) = conn.read_packet() {
                        conn.max_frame_size.store(max_frame_size, Ordering::Release);
                        cli.println("Successfully logged in");
                    } else {
                        cli.println("Authentication failed");
                        continue;
                    }
                } else {
                    cli.println("Received weird packet in login sequence");
                    continue;
                }
                break 'outer conn;
            },
            Err(_) => {
                println!("Connecting failed, retrying in 10 seconds.");
                thread::sleep(Duration::from_secs(10));
            },
        }
    };
    let meta = Meta::load();
    let client = Arc::new(Client {
        cfg,
        conn,
        cli,
        running: AtomicBool::new(true),
        meta: SwapIt::new(meta),
    });
    let t_cli = client.cli.clone();
    let t_client = client.clone();
    thread::spawn(move || {
        loop {
            match t_cli.await_input(&t_client) {
                Ok(_) => {},
                Err(_) => {
                    t_cli.println("Failed to await input");
                },
            }
        }
    });
    let client2 = client.clone();
    thread::spawn(move || {
        let client = client2;
        loop {
            let packet = client.conn.read_packet().unwrap();
            match packet {
                PacketIn::ChallengeRequest { .. } => unreachable!(),
                PacketIn::LoginSuccess { .. } => unreachable!(),
                PacketIn::KeepAlive => {
                    client.conn.last_keep_alive.store(current_time_millis() as u64, Ordering::Release);
                },
                PacketIn::ConfirmBackup => {
                    
                },
                PacketIn::FrameRequest => {
                    client.conn.acknowledged.store(true, Ordering::Release);
                },
            }
        }
    });
    let client2 = client.clone();
    thread::spawn(move || {
        let client = client2;
        loop {
            let dist = current_time_millis() - client.meta.load().last_update;
            if dist < Duration::from_days(1).as_millis() {
                thread::sleep(Duration::from_millis((Duration::from_days(1).as_millis() - dist) as u64));
            }
            client.println("Trying to initiate update...");
            let backup_start = current_time_millis();
            let mut fingerprints = HashMap::new();
            for path in client.cfg.load().backup_locations.iter() {
                if !Path::new(path).exists() {
                    continue;
                }
                let hash = calculate_fingerprint(path);
                fingerprints.insert(path.to_string(), hash);
            }
            let delta = 'outer: {
                for hash in fingerprints.iter() {
                    if client.meta.load().fingerprints.get(hash.0).map(|old| *old != *hash.1).unwrap_or(true) {
                        break 'outer true;
                    }
                }
                false
            };
            if !delta {
                client.println("No changes found, skipping backup...");
                let new_cfg = Meta {
                    fingerprints,
                    last_update: backup_start,
                };
                client.update_meta(new_cfg);
                continue;
            }
            client.println("Detected changes, starting backup...");
            let mut fingerprints = HashMap::new();
            for path in client.cfg.load().backup_locations.iter() {
                if !Path::new(path).exists() {
                    // FIXME: tell backup server that this just doesn't exist
                    client.println(&format!("Can't read \"{}\"", path));
                    continue;
                }

                let hash = calculate_fingerprint(path);
                fingerprints.insert(path.to_string(), hash);
                client.send_by_path(path);
            }
            let new_cfg = Meta {
                fingerprints,
                last_update: backup_start,
            };

            client.update_meta(new_cfg);
            client.println("Finished backup");
        }
    });
    while client.running.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(1000));
    }
}

fn calculate_fingerprint(path: &str) -> u64 {
    if Path::new(path).is_file() {
        const CHUNK_SIZE: usize = 1024 * 4 * 512;

        let mut hasher = blake3::Hasher::new();
        let mut file = File::open(path).unwrap();
        let mut buf = vec![0; CHUNK_SIZE];
        while let Ok(bytes) = file.read(&mut buf) {
            if bytes == 0 {
                break;
            }
            hasher.update(&buf[0..bytes]);
        }
        let mut result = [0; 8];
        hasher.finalize_xof().read_exact(&mut result).unwrap();
        return u64::from_ne_bytes(result);
    }
    if Path::new(path).is_dir() {
        let mut hasher = blake3::Hasher::new();
        let dir = fs::read_dir(path).unwrap();
        for file in dir {
            if let Ok(file) = file {
                hasher.update(&calculate_fingerprint(file.path().to_str().unwrap()).to_ne_bytes());
            }
        }
        let mut result = [0; 8];
        hasher.finalize_xof().read_exact(&mut result).unwrap();
        return u64::from_ne_bytes(result);
    }
    unreachable!()
}

pub struct Client {
    cfg: Arc<SwapIt<Config>>,
    meta: SwapIt<Meta>,
    pub conn: Arc<NetworkClient>,
    cli: Arc<CmdLineInterface<Arc<Client>>>,
    running: AtomicBool,
}

impl Client {

    pub fn println(&self, line: &str) {
        self.cli.println(line);
    }

    fn update_meta(&self, cfg: Meta) {
        cfg.store();
        self.meta.store(cfg);
    }

    fn send_by_path<P: AsRef<Path>>(&self, path: P) {
        let path = path.as_ref();
        println!("sending {:?}", path);
        if path.is_dir() {
            for file in fs::read_dir(path).unwrap() {
                if let Ok(file) = file {
                    self.send_by_path(file.path());
                } else {
                    // FIXME: how do we handle errors?
                    continue; 
                }
            }
        } else if path.is_file() {
            // FIXME: make this threshold configurable by the server
            const LARGE_THRESHOLD: u64 = 1024 * 1024 * 50;
            if path.metadata().unwrap().len() > LARGE_THRESHOLD {
                // split up file into digestible chunks
                let frames = path.metadata().unwrap().len().div_ceil(LARGE_THRESHOLD);
                let mut file = OpenOptions::new().read(true).open(path).unwrap();
                for i in 0..frames {
                    let mut content = vec![0; LARGE_THRESHOLD as usize];
                    file.read_exact(&mut content).unwrap();
                    let last_frame = i == frames - 1;
                    println!("delivered large frame");
                    self.conn.write_packet(packet::PacketOut::DeliverFrame { file_name: path.to_str().unwrap().to_string(), content, last_frame }).unwrap();
                    self.await_acknowledgement();
                    // FIXME: write a backup log so interrupted backups can be completed later on (but use the start time as the completion time to be stored in metadata)
                }
            } else {
                let content = fs::read(path).unwrap();
                println!("delivered small frame");
                self.conn.write_packet(packet::PacketOut::DeliverFrame { file_name: path.to_str().unwrap().to_string(), content, last_frame: true }).unwrap();
                self.await_acknowledgement();
                // FIXME: write a backup log so interrupted backups can be completed later on (but use the start time as the completion time to be stored in metadata)
            }
        }
    }

    fn await_acknowledgement(&self) {
        for _ in 0..10000 {
            if self.conn.acknowledged.load(Ordering::Acquire) {
                self.conn.acknowledged.store(false, Ordering::Release);
                return;
            }
            for _ in 0..10 {
                hint::spin_loop();
            }
        }
        while !self.conn.acknowledged.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
        self.conn.acknowledged.store(false, Ordering::Release);
    }

}

struct CmdHelp;

impl CommandImpl for CmdHelp {
    type CTX = Arc<Client>;

    fn execute(&self, ctx: &Self::CTX, _input: &[&str]) -> anyhow::Result<()> {
        ctx.println(&format!("Commands ({}):", ctx.cli.cmd_count()));
        for cmd in ctx.cli.cmds() {
            // FIXME: add parameter info to this list
            ctx.println(&format!("{}", cmd.name()));
        }
        Ok(())
    }
}