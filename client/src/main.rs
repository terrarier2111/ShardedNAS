use std::{fs, path::Path, sync::Arc, thread, time::Duration};

use clitty::{core::{CmdParamEnumConstraints, CmdParamStrConstraints, CommandBuilder, CommandImpl, CommandParam, CommandParamTy, EnumVal, UsageBuilder}, ui::{CLIBuilder, CmdLineInterface, PrintFallback}};
use config::{Config, RegisterCfg};
use network::NetworkClient;
use packet::PacketIn;
use protocol::PROTOCOL_VERSION;
use rsa::{pkcs1::DecodeRsaPrivateKey, sha2::{Digest, Sha256}, Pss, RsaPrivateKey};
use swap_it::SwapIt;

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
    let cfg = Config::load();
    let conn = 'outer: loop {
        match NetworkClient::new(cfg.dst.as_str(), cfg.port) {
            Ok(conn) => {
                conn.write_packet(packet::PacketOut::Login { token: creds.token.clone(), version: PROTOCOL_VERSION, }).unwrap();
                let packet = conn.read_packet();
                if let PacketIn::ChallengeRequest { challenge } = packet.unwrap() {
                    let mut hasher = Sha256::new();
                    hasher.update(&challenge);
                    let hashed = hasher.finalize();
                    let signed = RsaPrivateKey::from_pkcs1_der(&creds.priv_key).expect("Invalid private key").sign_with_rng(&mut rand::thread_rng(), Pss::new::<Sha256>(), &hashed).unwrap();
                    conn.write_packet(packet::PacketOut::ChallengeResponse { val: signed }).unwrap();
                    println!("sent response");
                    if let Ok(PacketIn::LoginSuccess) = conn.read_packet() {
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
    let client = Arc::new(Client {
        cfg: SwapIt::new(cfg),
        conn: Arc::new(conn),
        cli,
        credentials: creds,
    });
    let client2 = client.clone();
    thread::spawn(move || {
        let client = client2;
        loop {
            let packet = client.conn.read_packet().unwrap();
            
        }
    });
}

pub struct Client {
    cfg: SwapIt<Config>,
    credentials: RegisterCfg,
    pub conn: Arc<NetworkClient>,
    cli: Arc<CmdLineInterface<Arc<Client>>>,
}

impl Client {

    pub fn println(&self, line: &str) {
        self.cli.println(line);
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