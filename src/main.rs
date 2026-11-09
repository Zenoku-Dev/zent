// main.rs — zent: Zenoku Post. Свой SMTP/POP3/IMAP, свой DNS, свой DKIM/SPF.
mod agent;
mod auth;
mod config;
mod dns;
mod dkim;
mod imap;
mod maildir;
mod mime;
mod pop3;
mod queue;
mod smtp;
mod spf;
mod tls;
mod util;

use std::sync::Arc;

use tokio::sync::RwLock;

use agent::AgentHub;
use auth::UserDb;
use config::Config;
use maildir::Store;
use queue::Queue;

/// Общее состояние сервера, доступное всем модулям.
pub struct Ctx {
    pub cfg: Config,
    pub users: RwLock<UserDb>,
    pub store: Store,
    pub acceptor: Option<tls::TlsAcceptor>,
    /// соединения с redmi: спам-скоринг нейронкой + репликация писем
    pub agent: Arc<AgentHub>,
    pub queue: Arc<Queue>,
}

fn default_cfg_path() -> String {
    if let Ok(p) = std::env::var("ZENT_CONFIG") {
        if !p.is_empty() {
            return p;
        }
    }
    if std::path::Path::new("/etc/zent/zent.conf").exists() {
        "/etc/zent/zent.conf".into()
    } else if std::path::Path::new("zent.conf").exists() {
        "zent.conf".into()
    } else {
        "/etc/zent/zent.conf".into()
    }
}

fn load_ctx(path: &str) -> Arc<Ctx> {
    let cfg = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zent: cannot load config {path}: {e}");
            std::process::exit(1);
        }
    };
    let acceptor = if cfg.has_tls() {
        match tls::load_acceptor(cfg.tls_cert.as_ref().unwrap(), cfg.tls_key.as_ref().unwrap()) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("zent: TLS disabled: {e}");
                None
            }
        }
    } else {
        None
    };
    let users = match UserDb::open(&cfg) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("zent: cannot open user db {:?}: {e}", cfg.db);
            std::process::exit(1);
        }
    };
    let store = Store::new(cfg.store.clone());
    let ctx = Ctx {
        cfg,
        users: RwLock::new(users),
        store,
        acceptor,
        agent: AgentHub::from_cfg_inner(path),
        queue: Queue::new_inner(path),
    };
    Arc::new(ctx)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "run" => run(args.get(2).map(|s| s.as_str()).unwrap_or(&default_cfg_path())).await,
        "user" => user_cmd(&args[2..]),
        "dns-records" => dns_records(&args[2..]),
        "queue" => queue_cmd(&args[2..]).await,
        "version" | "--version" => println!("zent 0.1.0 (Zenoku Post)"),
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("unknown command: {other}");
            usage();
        }
    }
}

fn usage() {
    eprintln!(
        "zent - Zenoku Post (свой SMTP/POP3/IMAP сервер)

usage:
  zent run [config]                    запуск сервера (default /etc/zent/zent.conf)
  zent user add <email> [--name N] [--pass P] [--owner ACCOUNT]
  zent user passwd <email> [--pass P]
  zent user rm <email>
  zent user list
  zent dns-records [config]            SPF/DKIM/DMARC TXT-записи для зоны
  zent queue list | flush [config]     очередь исходящих
  zent version"
    );
    std::process::exit(2);
}

async fn run(path: &str) {
    let ctx = load_ctx(path);
    let cfg = &ctx.cfg;
    eprintln!(
        "zent: hostname {} domains {:?} tls={} agent={}",
        cfg.hostname,
        cfg.domains,
        cfg.has_tls(),
        cfg.agent_addr.clone().unwrap_or_default()
    );
    std::fs::create_dir_all(&cfg.queue).ok();
    std::fs::create_dir_all(&cfg.store).ok();
    // восстановление писем с redmi, если локально пусто
    ctx.agent.restore_if_empty().await;
    // слушатель агентских соединений (redmi dial-in)
    {
        let c = ctx.clone();
        tokio::spawn(async move { agent::agent_listener(c).await });
    }
    // фоновая досылка несинхронизированных писем на redmi
    {
        let hub = ctx.agent.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                hub.flush_pending().await;
            }
        });
    }

    let mut tasks = Vec::new();
    if let Some(a) = cfg.smtp_addr.clone() {
        tasks.push(tokio::spawn(smtp::smtp_listener(
            ctx.clone(),
            a,
            smtp::SmtpKind::Inbound,
        )));
    }
    if let Some(a) = cfg.submission_addr.clone() {
        tasks.push(tokio::spawn(smtp::smtp_listener(
            ctx.clone(),
            a,
            smtp::SmtpKind::Submission,
        )));
    }
    if let Some(a) = cfg.smtps_addr.clone() {
        tasks.push(tokio::spawn(smtp::smtp_listener(
            ctx.clone(),
            a,
            smtp::SmtpKind::Smtps,
        )));
    }
    if let Some(a) = cfg.imap_addr.clone() {
        tasks.push(tokio::spawn(imap::imap_listener(ctx.clone(), a, false)));
    }
    if let Some(a) = cfg.imaps_addr.clone() {
        tasks.push(tokio::spawn(imap::imap_listener(ctx.clone(), a, true)));
    }
    if let Some(a) = cfg.pop3_addr.clone() {
        tasks.push(tokio::spawn(pop3::pop3_listener(ctx.clone(), a, false)));
    }
    if let Some(a) = cfg.pop3s_addr.clone() {
        tasks.push(tokio::spawn(pop3::pop3_listener(ctx.clone(), a, true)));
    }
    // очередь исходящих
    let q = ctx.queue.clone();
    let store = ctx.store.clone();
    let hostname = cfg.hostname.clone();
    let relay_host = cfg.relay_host.clone();
    let relay_port = cfg.relay_port;
    tokio::spawn(async move {
        queue::queue_loop(q, store, hostname, relay_host, relay_port).await;
    });

    if tasks.is_empty() {
        eprintln!("zent: все слушатели выключены в конфиге");
        return;
    }
    for t in tasks {
        let _ = t.await;
    }
}

fn user_cmd(args: &[String]) {
    let path = default_cfg_path();
    let cfg = Config::load(&path).expect("config");
    let mut db = UserDb::open(&cfg).expect("userdb");
    match args.first().map(|s| s.as_str()) {
        Some("add") => {
            let email = args.get(1).expect("email").clone();
            let mut name = String::new();
            let mut pass = String::new();
            let mut owner = String::new();
            let mut it = args.iter().skip(2);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--name" => name = it.next().cloned().unwrap_or_default(),
                    "--pass" => pass = it.next().cloned().unwrap_or_default(),
                    "--owner" => owner = it.next().cloned().unwrap_or_default(),
                    _ => {}
                }
            }
            if pass.is_empty() && !args.contains(&"--pass".to_string()) {
                eprint!("password (пусто = только в общей системе auth): ");
                std::io::Write::flush(&mut std::io::stderr()).ok();
                pass = read_line();
            }
            match db.add(&email, &pass, &name, &owner) {
                Ok(_) => {
                    crate::maildir::Store::new(&cfg.store).ensure_user(&email).ok();
                    println!("ok: {email} added");
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("passwd") => {
            let email = args.get(1).expect("email").clone();
            let mut pass = String::new();
            let mut it = args.iter().skip(2);
            while let Some(a) = it.next() {
                if a == "--pass" {
                    pass = it.next().cloned().unwrap_or_default();
                }
            }
            if pass.is_empty() {
                eprint!("new password for {email}: ");
                std::io::Write::flush(&mut std::io::stderr()).ok();
                pass = read_line();
            }
            match db.passwd(&email, &pass) {
                Ok(_) => println!("ok: password changed"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("rm") => {
            let email = args.get(1).expect("email").clone();
            match db.remove(&email) {
                Ok(_) => {
                    let _ = crate::maildir::Store::new(&cfg.store).remove_user(&email);
                    println!("ok: {email} removed");
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("list") => {
            for u in db.list() {
                let (msgs, bytes) = crate::maildir::Store::new(&cfg.store).user_stats(&u.email);
                println!(
                    "{}\towner={}\t{}\t{} msgs\t{} MB",
                    u.email,
                    u.owner,
                    u.name,
                    msgs,
                    bytes / 1_000_000
                );
            }
        }
        _ => usage(),
    }
}

/// TXT-записи для зоны: SPF, DKIM (публичный ключ), DMARC + напоминание про PTR.
fn dns_records(args: &[String]) {
    let path = args
        .first()
        .map(|s| s.as_str())
        .filter(|s| !s.starts_with('-'))
        .unwrap_or(&default_cfg_path())
        .to_string();
    let cfg = Config::load(&path).expect("config");
    let ip = args
        .iter()
        .position(|a| a == "--ip")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| {
            eprintln!("указание --ip A.B.C.D позволяет вставить адрес в SPF");
            String::new()
        });
    for dom in &cfg.domains {
        println!("; === {dom} ===");
        let ip_part = if ip.is_empty() {
            String::new()
        } else {
            format!(" ip4:{ip}")
        };
        println!("{dom}. 3600 IN TXT \"v=spf1 mx{ip_part} -all\"");
        let key = crate::dkim::ensure_keypair(&cfg.db, dom).expect("dkim keypair");
        println!(
            "{}._domainkey.{} 3600 IN TXT \"v=DKIM1; k=ed25519; p={}\"",
            cfg.dkim_selector, dom, key
        );
        println!(
            "_dmarc.{dom} 3600 IN TXT \"v=DMARC1; p=quarantine; adkim=r; aspf=r; fo=1\""
        );
    }
    println!(
        "; не забудь PTR (rDNS): {} -> {} (у провайдера VPS)",
        cfg.hostname, cfg.hostname
    );
}

async fn queue_cmd(args: &[String]) {
    let path = default_cfg_path();
    let cfg = Config::load(&path).expect("config");
    let q = queue::Queue::new_inner(&path);
    match args.first().map(|s| s.as_str()) {
        Some("list") => q.list(),
        Some("flush") => {
            let store = Store::new(cfg.store.clone());
            queue::queue_loop_once(q, store, cfg.hostname.clone(), cfg.relay_host.clone(), cfg.relay_port).await;
        }
        _ => usage(),
    }
}

fn read_line() -> String {
    let mut s = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(std::io::stdin()), &mut s).ok();
    s.trim().to_string()
}

// маленькие хелперы, чтобы не тянуть Config наружу из load_ctx
impl AgentHub {
    fn from_cfg_inner(path: &str) -> Arc<AgentHub> {
        let cfg = Config::load(path).expect("config");
        AgentHub::from_cfg(&cfg)
    }
}
impl Queue {
    fn new_inner(path: &str) -> Arc<Queue> {
        let cfg = Config::load(path).expect("config");
        Arc::new(Queue::new(&cfg))
    }
}
