#![feature(duration_constructors)]

use std::{
    fs, io::Read, path::Path, sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    }, thread, time::Duration
};

use clitty::{
    core::{
        CmdParamEnumConstraints, CmdParamStrConstraints, CommandBuilder, CommandImpl, CommandParam, CommandParamTy, EnumVal, UsageBuilder
    },
    ui::{CLIBuilder, CmdLineInterface, PrintFallback},
};
use config::{Config, MetaCfg, RegisterCfg};
use network::NetworkServer;
use rand::{thread_rng, Rng};
use rsa::{pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey}, RsaPrivateKey, RsaPublicKey};
use swap_it::SwapIt;
use utils::clear_dir;

mod config;
mod network;
mod packet;
mod protocol;
mod utils;

pub type Token = Vec<u8>;

#[tokio::main]
async fn main() {
    fs::create_dir_all("./nas/tmp").unwrap();
    clear_dir("./nas/tmp/").unwrap();
    let cfg = Config::load();
    let window = CLIBuilder::new()
        .prompt("SharedNAS: ".to_string())
        .command(
            CommandBuilder::new("tokens", CmdTokens).params(
                UsageBuilder::new().required(CommandParam {
                    name: "action",
                    ty: CommandParamTy::Enum(CmdParamEnumConstraints::IgnoreCase(
                        vec![
                            (
                                "register",
                                EnumVal::None,
                            ),
                            (
                                "unregister",
                                EnumVal::Complex(
                                    UsageBuilder::new()
                                        .required(CommandParam {
                                            name: "token",
                                            ty: CommandParamTy::String(
                                                CmdParamStrConstraints::None,
                                            ),
                                        })
                                        .optional(CommandParam {
                                            name: "delete",
                                            ty: CommandParamTy::String(
                                                CmdParamStrConstraints::None,
                                            ),
                                        }),
                                ),
                            ),
                            (
                                "list",
                                EnumVal::None,
                            )
                        ],
                    )),
                }),
            ),
        )
        .command(CommandBuilder::new("help", CmdHelp))
        .command(CommandBuilder::new("connections", CmdConnections))
        .fallback(Box::new(PrintFallback::new("This command doesn't exist".to_string())))
        .build();
    let cli = Arc::new(CmdLineInterface::new(window));
    let server = Arc::new(Server {
        running: AtomicBool::new(true),
        network: NetworkServer::new(cfg.port).await,
        cfg: SwapIt::new(cfg),
        cli: cli.clone(),
    });
    server.network.listen_login(server.clone()).await;
    let srv = server.clone();
    thread::spawn(move || {
        let cli = cli;
        loop {
            match cli.await_input(&srv) {
                Ok(_) => {},
                Err(err) => {
                    cli.println(&format!("An CLI error occoured: {err}"));
                },
            }
        }
    });
    while server.is_running() {
        thread::sleep(Duration::from_millis(50));
    }
    // give the rest of the server time to properly shut down
    thread::sleep(Duration::from_millis(50));
}

pub struct Server {
    running: AtomicBool,
    cfg: SwapIt<Config>,
    network: NetworkServer,
    cli: Arc<CmdLineInterface<Arc<Server>>>,
}

impl Server {
    pub fn update_cfg(&self, cfg: Config) {
        self.cfg.store(cfg.clone());
        fs::write("./nas/config.json", serde_json::to_string(&cfg).unwrap()).unwrap();
    }

    fn gen_token(&self) -> (Token, RsaPrivateKey) {
        loop {
            let token = rand::thread_rng().gen::<[u8; 32]>();
            let token = Vec::from_iter(token);
            if !self.is_trusted(&token) {
                let mut rng = rand::thread_rng();
                let bits = 4096;
                let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
                return (token, priv_key);
            }
        }
    }

    pub fn is_trusted(&self, token: &Token) -> bool {
        self.cfg.load().tokens.contains(token)
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
    }

    pub fn println(&self, msg: &str) {
        self.cli.println(msg);
    }
}

struct CmdTokens;

impl CommandImpl for CmdTokens {
    type CTX = Arc<Server>;

    fn execute(&self, ctx: &Self::CTX, input: &[&str]) -> anyhow::Result<()> {
        match input[0] {
            "register" => {
                let (token, priv_key) = ctx.gen_token();
                let token_str = binary_to_hash(&token);
                if !Path::new(&format!("./nas/instances/{}/storage", &token_str)).exists() {
                    ctx.println("Creating file structure...");
                    fs::create_dir_all(format!("./nas/instances/{}/storage", &token_str)).unwrap();
                    fs::write(
                        format!("./nas/instances/{}/meta.json", &token_str),
                        serde_json::to_string(&MetaCfg {
                            last_updates: vec![],
                            pub_key: priv_key.to_public_key().to_pkcs1_der().unwrap().into_vec(),
                        })
                        .unwrap()
                        .as_bytes(),
                    )
                    .unwrap();
                }
                ctx.println("Adding token...");
                let mut meta = ctx.cfg.load().clone();
                meta.tokens.insert(token.clone());
                ctx.update_cfg(meta);

                ctx.println(&format!("Created token {} successfully", &token_str));
                ctx.println("The token information, needed by the client was written into a file at ./nas/tmp/credentials.json");
                fs::write("./nas/tmp/credentials.json", serde_json::to_string(&RegisterCfg { priv_key: priv_key.to_pkcs1_der().unwrap().to_bytes().to_vec(), token }).unwrap()).unwrap();
                Ok(())
            }
            "unregister" => {
                let token = token_from_str(input[1]);
                let delete = input.get(2).unwrap_or(&"false").parse::<bool>()?;
                if !ctx.is_trusted(&token) {
                    ctx.println(&format!("There is no token called {}", input[1]));
                    return Ok(());
                }
                ctx.println("Removing token...");
                let mut meta = ctx.cfg.load().clone();
                meta.tokens.remove(&token);
                ctx.update_cfg(meta);
                if delete {
                    ctx.println("Deleting backup...");
                    fs::remove_dir_all(format!("./nas/instances/{}", input[1])).unwrap();
                }
                ctx.println("Deleted token successfully");
                Ok(())
            }
            "list" => {
                let cfg = ctx.cfg.load();
                ctx.println(&format!("Tokens ({}):", cfg.tokens.len()));
                for token in cfg.tokens.iter() {
                    let token_str = binary_to_str(token);
                    ctx.println(&format!("{}", token_str));
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }
}

pub fn binary_to_hash(token: &Token) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(token);
    let mut bin = [0; 8];
    hasher.finalize_xof().fill(&mut bin);
    u64::from_ne_bytes(bin).to_string()
}

pub fn binary_to_str(token: &Token) -> String {
    let mut raw = String::new();
    for num in token.iter() {
        raw.push_str(num.to_string().as_str());
        raw.push('_');
    }
    raw.pop();
    raw
}

pub fn token_from_str(raw: &str) -> Token {
    let mut out = vec![];
    for part in raw.split('_') {
        out.push(part.parse::<u8>().unwrap());
    }
    out
}

struct CmdHelp;

impl CommandImpl for CmdHelp {
    type CTX = Arc<Server>;

    fn execute(&self, ctx: &Self::CTX, _input: &[&str]) -> anyhow::Result<()> {
        ctx.println(&format!("Commands ({}):", ctx.cli.cmd_count()));
        for cmd in ctx.cli.cmds() {
            // FIXME: add parameter info to this list
            ctx.println(&format!("{}", cmd.name()));
        }
        Ok(())
    }
}

struct CmdConnections;

impl CommandImpl for CmdConnections {
    type CTX = Arc<Server>;

    fn execute(&self, ctx: &Self::CTX, _input: &[&str]) -> anyhow::Result<()> {
        let clients = ctx.network.clients.blocking_lock();
        ctx.println(&format!("Connections ({}):", clients.len()));
        for conn in clients.iter() {
            ctx.println(&format!("{}: {}", binary_to_str(&conn.id), conn.addr));
        }
        Ok(())
    }
}
