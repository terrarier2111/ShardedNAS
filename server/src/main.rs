use std::{fs, sync::{atomic::{AtomicBool, Ordering}, Arc}, thread, time::Duration};

use clitty::{core::{CmdParamStrConstraints, CommandBuilder, CommandImpl, CommandParam, CommandParamTy, EnumVal, UsageBuilder}, ui::{CLIBuilder, CmdLineInterface}};
use config::{Config, MetaCfg};
use network::NetworkServer;
use swap_it::SwapIt;

mod protocol;
mod packet;
mod network;
mod config;
mod utils;

pub type Token = Vec<u8>;

#[tokio::main]
async fn main() {
    fs::create_dir_all("./nas").unwrap();
    let cfg = Config::load();
    let window = CLIBuilder::new().prompt("SharedNAS: ".to_string()).command(CommandBuilder::new("tokens", CmdTokens).params(UsageBuilder::new().required(CommandParam { name: "action", ty: CommandParamTy::Enum(clitty::core::CmdParamEnumConstraints::IgnoreCase(vec![("register", EnumVal::Simple(CommandParamTy::String(CmdParamStrConstraints::None))), ("unregister", EnumVal::Complex(UsageBuilder::new().required(CommandParam { name: "token", ty: CommandParamTy::String(CmdParamStrConstraints::None) }).optional(CommandParam { name: "delete", ty: CommandParamTy::String(CmdParamStrConstraints::None) })))])) }))).build();
    let cli = Arc::new(CmdLineInterface::new(window));
    let server = Arc::new(Server { running: AtomicBool::new(false), network: NetworkServer::new(cfg.port).await, cfg: SwapIt::new(cfg), cli: cli.clone() });
    server.network.listen_login(server.clone()).await;
    let srv = server.clone();
    thread::spawn(move || {
        let cli = cli;
        cli.await_input(&srv).unwrap();
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
                let token = token_from_str(input[1]);
                if !ctx.is_trusted(&token) {
                    ctx.println(&format!("The token `{}` is already registerd", input[1]));
                    return Ok(());
                }
                ctx.println("Creating file structure...");
                fs::create_dir_all(format!("./nas/instances/{}/storage", input[1])).unwrap();
                fs::write(format!("./nas/instances/{}/meta.json", input[1]), serde_json::to_string(&MetaCfg { last_updates: vec![] }).unwrap().as_bytes()).unwrap();
                ctx.println("Adding token...");
                let mut meta = ctx.cfg.load().clone();
                meta.tokens.insert(token);
                ctx.update_cfg(meta);
                
                ctx.println("Created token successfully");
                Ok(())
            },
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
            },
            "list" => {
                let cfg = ctx.cfg.load();
                ctx.println(&format!("Tokens ({}):", cfg.tokens.len()));
                for token in cfg.tokens.iter() {
                    let token_str = token_to_str(token);
                    ctx.println(&format!("{}", token_str));
                }
                Ok(())
            },
            _ => unreachable!(),
        }
    }
}

pub fn token_to_str(token: &Token) -> String {
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