// config.rs — конфиг zent: плоский key = value, всё своё (без serde/toml).
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub hostname: String,
    pub domains: Vec<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub db: PathBuf,
    pub store: PathBuf,
    pub queue: PathBuf,
    pub max_message: u64,
    pub smtp_addr: Option<String>,
    pub submission_addr: Option<String>,
    pub smtps_addr: Option<String>,
    pub imap_addr: Option<String>,
    pub imaps_addr: Option<String>,
    pub pop3_addr: Option<String>,
    pub pop3s_addr: Option<String>,
    pub relay_host: Option<String>,
    pub relay_port: u16,
    pub relay_user: Option<String>,
    pub relay_pass: Option<String>,
    pub dkim_selector: String,
    pub dmarc_reject: bool,
    // общая система аутентификации (rival-auth)
    pub auth_url: String,
    pub auth_mode: String, // "auth" | "local"
    pub agent_addr: Option<String>,
    pub agent_token: String,
    pub ml_threshold: f64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hostname: "localhost".into(),
            domains: vec![],
            tls_cert: None,
            tls_key: None,
            db: PathBuf::from("/var/lib/zent"),
            store: PathBuf::from("/var/lib/zent/mail"),
            queue: PathBuf::from("/var/lib/zent/queue"),
            max_message: 26_214_400,
            smtp_addr: Some("0.0.0.0:25".into()),
            submission_addr: Some("0.0.0.0:587".into()),
            smtps_addr: Some("0.0.0.0:465".into()),
            imap_addr: Some("0.0.0.0:143".into()),
            imaps_addr: Some("0.0.0.0:993".into()),
            pop3_addr: Some("0.0.0.0:110".into()),
            pop3s_addr: Some("0.0.0.0:995".into()),
            relay_host: None,
            relay_port: 25,
            relay_user: None,
            relay_pass: None,
            dkim_selector: "zent".into(),
            dmarc_reject: true,
            auth_url: "https://auth.rival-afk.com".into(),
            auth_mode: "auth".into(),
            agent_addr: Some("0.0.0.0:7666".into()),
            agent_token: String::new(),
            ml_threshold: 0.65,
        }
    }
}

fn split_val(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once('=')?;
    let k = k.trim().to_lowercase();
    let v = v.trim().trim_matches('"').to_string();
    Some((k, v))
}

impl Config {
    pub fn load(path: &str) -> std::io::Result<Config> {
        let raw = std::fs::read_to_string(path)?;
        let mut kv: HashMap<String, String> = HashMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = split_val(line) {
                kv.insert(k, v);
            }
        }
        let mut c = Config::default();
        let get = |k: &str| kv.get(k).map(|s| s.trim().to_string());
        let nonempty = |k: &str| get(k).filter(|s| !s.is_empty());

        if let Some(v) = nonempty("hostname") { c.hostname = v; }
        if let Some(v) = get("domains") {
            c.domains = v
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }
        c.tls_cert = nonempty("tls_cert").map(PathBuf::from);
        c.tls_key = nonempty("tls_key").map(PathBuf::from);
        if let Some(v) = nonempty("db") { c.db = PathBuf::from(v); }
        if let Some(v) = nonempty("store") { c.store = PathBuf::from(v); }
        if let Some(v) = nonempty("queue") { c.queue = PathBuf::from(v); }
        if let Some(v) = get("max_message") {
            if let Ok(n) = v.parse() { c.max_message = n; }
        }
        // пустое значение = слушатель выключен
        c.smtp_addr = nonempty("smtp_addr");
        c.submission_addr = nonempty("submission_addr");
        c.smtps_addr = nonempty("smtps_addr");
        c.imap_addr = nonempty("imap_addr");
        c.imaps_addr = nonempty("imaps_addr");
        c.pop3_addr = nonempty("pop3_addr");
        c.pop3s_addr = nonempty("pop3s_addr");
        c.relay_host = nonempty("relay_host");
        if let Some(v) = get("relay_port") {
            if let Ok(n) = v.parse() { c.relay_port = n; }
        }
        c.relay_user = nonempty("relay_user");
        c.relay_pass = nonempty("relay_pass");
        if let Some(v) = nonempty("dkim_selector") { c.dkim_selector = v; }
        if let Some(v) = nonempty("auth_url") { c.auth_url = v; }
        if let Some(v) = nonempty("auth_mode") { c.auth_mode = v; }
        if let Some(v) = get("dmarc_reject") {
            c.dmarc_reject = matches!(v.to_lowercase().as_str(), "yes" | "true" | "1" | "on");
        }
        c.agent_addr = nonempty("agent_addr");
        if let Some(v) = get("agent_token") { c.agent_token = v.trim().to_string(); }
        if let Some(v) = get("ml_threshold") {
            if let Ok(n) = v.parse() { c.ml_threshold = n; }
        }
        if c.domains.is_empty() {
            // по умолчанию — домен из hostname без mail./smtp. префикса
            let dom = c
                .hostname
                .split_once('.')
                .map(|(_, rest)| rest.to_string())
                .unwrap_or_else(|| c.hostname.clone());
            c.domains = vec![dom];
        }
        Ok(c)
    }

    pub fn is_local_domain(&self, dom: &str) -> bool {
        let d = dom.trim_end_matches('.').to_lowercase();
        self.domains.iter().any(|x| *x == d)
    }

    pub fn has_tls(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}
