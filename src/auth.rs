// auth.rs — реестр почтовых ящиков + проверка пароля в ОБЩЕЙ системе
// аутентификации (auth.rival-afk.com, POST /v1/web/passlogin).
//  - 200/403 (нет консольных кап) = пароль верный, 401 = неверный;
//  - ответ кэшируется на 5 минут;
//  - при недоступности auth-сервера — откат на локальный hash (если задан
//    через `zent user add --pass`), иначе TempFail;
//  - владение ящиками: обычный юзер владеет ровно username@<домен>; аккаунт
//    с ролью admin/owner может владеть любым количеством ящиков на локальных
//    доменах (owner в реестре; логин с полным адресом, пароль владельца);
//  - после успешного логина ящик автосоздаётся (autoprovision).
// Сетевой клиент — свой sync HTTPS/1.1 поверх rustls (без reqwest).
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use crate::config::Config;
use crate::util::{hash_password, now, verify_password};

#[derive(Debug, Clone)]
pub struct User {
    pub email: String,
    pub hash: String, // пусто = пароль только в общей системе
    pub name: String,
    pub created: u64,
    pub owner: String, // логин аккаунта общей системы (пусто = local part)
}

#[derive(Debug, Clone)]
pub enum AuthVerdict {
    /// пароль верный; роль аккаунта ("user"|"admin"|"owner")
    Ok(String),
    BadCreds,
    TempFail,
}

impl AuthVerdict {
    pub fn is_admin(&self) -> bool {
        matches!(self, AuthVerdict::Ok(r) if r == "admin" || r == "owner")
    }
}

pub struct AuthClient {
    pub url: String, // https://auth.rival-afk.com
    cache: Mutex<HashMap<String, (u64, bool, String)>>,
    cache_secs: u64,
    /// 0 = ещё не проверяли связь, 1 = жив, 2 = мёртв
    alive: AtomicU8,
}

impl AuthClient {
    pub fn new(url: &str) -> AuthClient {
        AuthClient {
            url: url.trim_end_matches('/').to_string(),
            cache: Mutex::new(HashMap::new()),
            cache_secs: 300,
            alive: AtomicU8::new(0),
        }
    }

    pub fn verify(&self, username: &str, pass: &str) -> AuthVerdict {
        let u = username.to_lowercase();
        if let Ok(c) = self.cache.lock() {
            if let Some((ts, ok, role)) = c.get(&u) {
                if now() - *ts < self.cache_secs {
                    return if *ok {
                        AuthVerdict::Ok(role.clone())
                    } else {
                        AuthVerdict::BadCreds
                    };
                }
            }
        }
        let verdict = self.remote(&u, pass);
        match &verdict {
            AuthVerdict::Ok(role) => {
                if let Ok(mut c) = self.cache.lock() {
                    c.insert(u, (now(), true, role.clone()));
                }
            }
            AuthVerdict::BadCreds => {
                if let Ok(mut c) = self.cache.lock() {
                    c.insert(u, (now(), false, String::new()));
                }
            }
            AuthVerdict::TempFail => {}
        }
        verdict
    }

    fn remote(&self, username: &str, pass: &str) -> AuthVerdict {
        let body = format!(
            "{{\"username\":\"{}\",\"password\":\"{}\"}}",
            json_escape(username),
            json_escape(pass)
        );
        match http_post_json(&format!("{}/v1/web/passlogin", self.url), &body) {
            Ok((code, resp)) => {
                self.alive.store(1, Ordering::Relaxed);
                match code {
                    200 => AuthVerdict::Ok(json_str(&resp, "role").unwrap_or("user".into())),
                    // 403 = пароль верный, просто нет console/ssh кап
                    403 => AuthVerdict::Ok(json_str(&resp, "role").unwrap_or("user".into())),
                    401 => AuthVerdict::BadCreds,
                    _ => AuthVerdict::TempFail,
                }
            }
            Err(e) => {
                if self.alive.load(Ordering::Relaxed) != 2 {
                    eprintln!("auth: {} unreachable: {}", self.url, e);
                }
                self.alive.store(2, Ordering::Relaxed);
                AuthVerdict::TempFail
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Грубое чтение строкового поля из JSON-ответа: "key":"value"
fn json_str(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":", key);
    let idx = s.find(&pat)? + pat.len();
    let rest = &s[idx..];
    let start = rest.find('"')?;
    let rest = &rest[start + 1..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next().unwrap_or('\\')),
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    Some(out)
}

/// Минимальный HTTPS/1.1 POST на rustls (ring). Возвращает (код, тело).
fn http_post_json(url: &str, body: &str) -> Result<(u16, String), String> {
    use std::io::{Read, Write};
    let rest = url.strip_prefix("https://").ok_or("only https supported")?;
    let (hostport, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{}", p)));
    let (host, port) = hostport
        .split_once(':')
        .map_or((hostport, 443u16), |(h, p)| {
            (h, p.parse::<u16>().unwrap_or(443))
        });

    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("no addr")?;
    let tcp = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| "bad server name")?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), server_name)
        .map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host,
        body.len(),
        body
    );
    tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&chunk[..n]);
                if resp.len() > 1 << 20 {
                    break;
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let text = String::from_utf8_lossy(&resp);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("bad http response")?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

pub struct UserDb {
    path: PathBuf,
    inner: Mutex<BTreeMap<String, User>>,
    pub auth: Option<AuthClient>,
}

impl UserDb {
    pub fn open(cfg: &Config) -> std::io::Result<UserDb> {
        std::fs::create_dir_all(&cfg.db)?;
        let path = cfg.db.join("users");
        let mut users = BTreeMap::new();
        if let Ok(raw) = std::fs::read_to_string(&path) {
            for line in raw.lines() {
                let f: Vec<&str> = line.split('\t').collect();
                if f.len() < 2 {
                    continue;
                }
                let email = f[0].to_string();
                let owner = f
                    .get(4)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| email.split('@').next().unwrap_or("").to_string());
                users.insert(
                    email.to_lowercase(),
                    User {
                        email,
                        hash: f[1].to_string(),
                        name: f.get(2).unwrap_or(&"").to_string(),
                        created: f.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
                        owner,
                    },
                );
            }
        }
        let auth = match cfg.auth_mode.as_str() {
            "local" => None,
            _ => Some(AuthClient::new(&cfg.auth_url)),
        };
        Ok(UserDb {
            path,
            inner: Mutex::new(users),
            auth,
        })
    }

    fn flush(&self, users: &BTreeMap<String, User>) -> std::io::Result<()> {
        let mut out = String::new();
        for u in users.values() {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                u.email, u.hash, u.name, u.created, u.owner
            ));
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, &self.path)
    }

    fn snapshot(&self) -> BTreeMap<String, User> {
        self.inner.lock().unwrap().clone()
    }

    /// Ящики, которыми владеет аккаунт общей системы.
    pub fn owned_by(&self, owner: &str) -> Vec<User> {
        self.snapshot()
            .values()
            .filter(|u| u.owner == owner.to_lowercase())
            .cloned()
            .collect()
    }

    pub fn exists(&self, email: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .contains_key(&email.to_lowercase())
    }

    pub fn get(&self, email: &str) -> Option<User> {
        self.inner
            .lock()
            .unwrap()
            .get(&email.to_lowercase())
            .cloned()
    }

    fn autoprovision(&self, email: &str, owner: &str, name: &str) {
        let mut map = self.inner.lock().unwrap();
        let key = email.to_lowercase();
        if map.contains_key(&key) {
            return;
        }
        map.insert(
            key,
            User {
                email: email.to_string(),
                hash: String::new(),
                name: name.to_string(),
                created: now(),
                owner: owner.to_string(),
            },
        );
        let snap = map.clone();
        self.flush(&snap).ok();
    }

    pub fn add(&mut self, email: &str, pass: &str, name: &str, owner: &str) -> Result<(), String> {
        let email = email.to_lowercase();
        if !email.contains('@') || email.contains(' ') {
            return Err(format!("bad email: {email}"));
        }
        let mut map = self.inner.lock().unwrap();
        if map.contains_key(&email) {
            return Err(format!("user {email} already exists"));
        }
        let hash = if pass.is_empty() {
            String::new() // пароль только в общей системе
        } else {
            if pass.len() < 6 {
                return Err("password too short (min 6)".into());
            }
            hash_password(pass)
        };
        let owner = if owner.is_empty() {
            email.split('@').next().unwrap_or("").to_string()
        } else {
            owner.to_string()
        };
        map.insert(
            email.clone(),
            User {
                email,
                hash,
                name: name.to_string(),
                created: now(),
                owner,
            },
        );
        self.flush(&map).map_err(|e| e.to_string())
    }

    pub fn remove(&mut self, email: &str) -> Result<(), String> {
        let email = email.to_lowercase();
        let mut map = self.inner.lock().unwrap();
        if map.remove(&email).is_none() {
            return Err(format!("user {email} not found"));
        }
        self.flush(&map).map_err(|e| e.to_string())
    }

    pub fn passwd(&mut self, email: &str, pass: &str) -> Result<(), String> {
        let email = email.to_lowercase();
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(&email) {
            Some(u) => {
                u.hash = hash_password(pass);
                self.flush(&map).map_err(|e| e.to_string())
            }
            None => Err(format!("user {email} not found")),
        }
    }

    pub fn list(&self) -> Vec<User> {
        self.snapshot().values().cloned().collect()
    }

    /// Проверка логина/пароля через общую систему аутентификации.
    ///
    /// Логин:
    ///   - "user"       -> ящик user@default_domain (владелец user);
    ///   - "admin@dom"  -> ящик admin@dom, владелец из реестра (напр. rival);
    ///     если ящика ещё нет и аккаунт админ — автосоздаём (owner=логин).
    /// Права: обычный юзер — только username@<default_domain>; админ/owner —
    /// любые локальные ящики со своим владельцем. Пароль всегда от аккаунта.
    pub fn verify(&self, login: &str, pass: &str, default_domain: Option<&str>) -> Option<User> {
        let login = login.trim().to_lowercase();
        if login.is_empty() || login.contains(' ') {
            return None;
        }
        let (email, owner): (String, String) = if login.contains('@') {
            match self.get(&login) {
                Some(u) => (login.clone(), u.owner),
                None => (
                    login.clone(),
                    login.split('@').next().unwrap_or("").to_string(),
                ),
            }
        } else {
            let d = default_domain?;
            (format!("{}@{}", login, d), login.clone())
        };

        if let Some(auth) = &self.auth {
            match auth.verify(&owner, pass) {
                verdict @ AuthVerdict::Ok(_) => {
                    let is_admin = verdict.is_admin();
                    let default_mb = format!("{}@{}", owner, default_domain.unwrap_or(""));
                    let allowed = is_admin || email == default_mb;
                    if !allowed {
                        return None;
                    }
                    if self.get(&email).is_none() {
                        self.autoprovision(&email, &owner, &owner);
                    }
                    return self.get(&email);
                }
                AuthVerdict::BadCreds => return None,
                AuthVerdict::TempFail => { /* локальный fallback ниже */ }
            }
        }
        // fallback: локальный hash (режим local или недоступный auth)
        let u = self.get(&email)?;
        if u.hash.is_empty() {
            return None;
        }
        if verify_password(pass, &u.hash) {
            Some(u)
        } else {
            None
        }
    }
}
