#![feature(duration_constructors)]

use std::{
    collections::HashMap, fs::{self, File, OpenOptions}, io::Read, path::Path, sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    }, thread, time::Duration
};

use clitty::{
    core::{CommandBuilder, CommandImpl},
    ui::{CLIBuilder, CmdLineInterface, PrintFallback},
};
use config::{Config, Meta, RegisterCfg};
use network::{connect, NetworkClient};
use swap_it::SwapIt;
use utils::current_time_millis;

mod config;
mod network;
mod packet;
mod protocol;
mod utils;

pub type Token = Vec<u8>;

fn main() {
    let window = CLIBuilder::new()
        .prompt("SharedNAS: ".to_string())
        .command(CommandBuilder::new("help", CmdHelp))
        .fallback(Box::new(PrintFallback::new(
            "This command doesn't exist".to_string(),
        )))
        .build();
    let cli = Arc::new(CmdLineInterface::new(window));
    let dir_path = "./nas/";
    fs::create_dir_all(dir_path).unwrap();
    let cfg = Arc::new(SwapIt::new(Config::load()));
    if !Path::new(RegisterCfg::PATH).exists() {
        cli.println("Got no credentials, shutting down in 10 seconds...");
        thread::sleep(Duration::from_secs(10));
        return;
    }
    let creds = RegisterCfg::load().unwrap().unwrap();
    let meta = Meta::load();
    let client = Arc::new(Client {
        cfg,
        cli,
        running: AtomicBool::new(true),
        meta: SwapIt::new(meta),
    });
    let t_cli = client.cli.clone();
    let t_client = client.clone();
    thread::spawn(move || loop {
        match t_cli.await_input(&t_client) {
            Ok(_) => {}
            Err(_) => {
                t_cli.println("Failed to await input");
            }
        }
    });
    let client2 = client.clone();
    thread::spawn(move || {
        let client = client2;
        loop {
            let dist = current_time_millis() - client.meta.load().last_update;
            if dist < Duration::from_days(1).as_millis() {
                thread::sleep(Duration::from_millis(
                    (Duration::from_days(1).as_millis() - dist) as u64,
                ));
            }
            client.println("Trying to initiate update...");
            let backup_start = current_time_millis();
            let meta = client.meta.load();
            let mut net_client = None;
            let mut fingerprints = HashMap::new();
            for path in client.cfg.load().backup_locations.iter() {
                if !Path::new(path).exists() {
                    // FIXME: tell backup server that this just doesn't exist
                    client.println(&format!("Can't read \"{}\"", path));
                    continue;
                }
                let hash = calculate_fingerprint(path);
                fingerprints.insert(path.to_string(), hash);
                if meta.fingerprints.get(path).cloned() != Some(hash) {
                    if net_client.is_none() {
                        let new_client = connect(&creds, &client).unwrap();
                        new_client
                            .write_packet(packet::PacketOut::BackupRequest)
                            .unwrap();
                        new_client.await_acknowledgement();
                        net_client = Some(new_client);
                    }
                    send_by_path(net_client.as_ref().unwrap(), path);
                }
            }

            if let Some(net_client) = net_client {
                let _ = net_client.write_packet(packet::PacketOut::FinishedBackup);
                let _ = net_client.shutdown();
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

fn send_by_path<P: AsRef<Path>>(conn: &NetworkClient, path: P) {
    let path = path.as_ref();
    println!("sending {:?}", path);
    if path.is_dir() {
        for file in fs::read_dir(path).unwrap() {
            if let Ok(file) = file {
                send_by_path(conn, file.path());
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
                conn
                    .write_packet(packet::PacketOut::DeliverFrame {
                        file_name: path.to_str().unwrap().to_string(),
                        content,
                        last_frame,
                    })
                    .unwrap();
                conn.await_acknowledgement();
                // FIXME: write a backup log so interrupted backups can be completed later on (but use the start time as the completion time to be stored in metadata)
            }
        } else {
            let content = fs::read(path).unwrap();
            println!("delivered small frame");
            conn
                .write_packet(packet::PacketOut::DeliverFrame {
                    file_name: path.to_str().unwrap().to_string(),
                    content,
                    last_frame: true,
                })
                .unwrap();
            conn.await_acknowledgement();
            // FIXME: write a backup log so interrupted backups can be completed later on (but use the start time as the completion time to be stored in metadata)
        }
    }
}
