// agent.rs — связь с redmi без rsh: телефон сам подключается к VPS (agent_addr)
// и держит постоянное соединение. По нему идут: скоринг писем нейронкой
// (zent-ml, живёт на телефоне) и синхронизация Maildir (tar-потоки).
// Протокол (после строки авторизации "AGENT <token>"):
//   SCORE <n>\n<n байт текста>        -> SCORE <0.87|-|>\n
//   SYNC <user> <n>\n<n байт tar>     -> SYNC OK\n | SYNC ERR\n
//   RESTORE\n                         -> RESTORE <n>\n<n байт tar> (0 = пусто)
//   PING\n (keepalive, ответа нет)
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use crate::config::Config;

type ReqTx = mpsc::Sender<Req>;

enum Req {
    Score(String, oneshot::Sender<Option<f64>>),
    Sync(String, Vec<u8>, oneshot::Sender<bool>),
    Restore(oneshot::Sender<Option<Vec<u8>>>),
}

struct AgentConn {
    tx: ReqTx,
}

impl Clone for AgentConn {
    fn clone(&self) -> Self {
        AgentConn { tx: self.tx.clone() }
    }
}

pub struct AgentHub {
    pub token: String,
    pub enabled: bool,
    pub store_root: PathBuf,
    conns: AsyncMutex<Vec<AgentConn>>,
    /// несинхронизированные юзеры (std Mutex — нужен из sync mark_dirty)
    pending: std::sync::Mutex<VecDeque<String>>,
}

const MAX_PENDING: usize = 256;

fn safe_component(user: &str) -> String {
    user.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl AgentHub {
    pub fn from_cfg(cfg: &Config) -> Arc<AgentHub> {
        Arc::new(AgentHub {
            token: cfg.agent_token.clone(),
            enabled: cfg.agent_addr.is_some(),
            store_root: cfg.store.clone(),
            conns: AsyncMutex::new(Vec::new()),
            pending: std::sync::Mutex::new(VecDeque::new()),
        })
    }

    pub fn online(&self) -> usize {
        self.conns.try_lock().map(|c| c.len()).unwrap_or(0)
    }

    async fn with_conn<T>(
        &self,
        f: impl FnOnce(ReqTx) -> Option<oneshot::Receiver<T>>,
    ) -> Option<T> {
        let tx = {
            let conns = self.conns.lock().await;
            conns.first().map(|c| c.tx.clone())?
        };
        let rx = f(tx)?;
        Some(
            tokio::time::timeout(std::time::Duration::from_secs(30), rx)
                .await
                .ok()?
                .ok()?,
        )
    }

    /// Оценка письма нейронкой на телефоне. None — агент недоступен (fail-open).
    pub async fn score(&self, text: &str) -> Option<f64> {
        let text: String = text.chars().take(16000).collect();
        self.with_conn(|tx| {
            let (tx2, rx) = oneshot::channel();
            match tx.try_send(Req::Score(text, tx2)) {
                Ok(_) => Some(rx),
                Err(_) => None,
            }
        })
        .await
        .flatten()
    }

    /// Отправить Maildir юзера на телефон.
    pub async fn sync_user(&self, user: &str, tar: Vec<u8>) -> bool {
        let user = user.to_lowercase();
        let sent = self
            .with_conn(|tx| {
                let (tx2, rx) = oneshot::channel();
                match tx.try_send(Req::Sync(user.clone(), tar, tx2)) {
                    Ok(_) => Some(rx),
                    Err(_) => None,
                }
            })
            .await
            .unwrap_or(false);
        if !sent {
            self.mark_dirty(&user);
            return false;
        }
        true
    }

    pub fn mark_dirty(&self, user: &str) {
        let u = user.to_lowercase();
        let mut p = self.pending.lock().unwrap();
        if !p.iter().any(|x| *x == u) {
            if p.len() >= MAX_PENDING {
                p.pop_front();
            }
            p.push_back(u);
        }
    }

    /// Прогнать все отложенные синки (фоновый таск).
    pub async fn flush_pending(&self) {
        let users: Vec<String> = {
            let mut p = self.pending.lock().unwrap();
            let out: Vec<String> = p.iter().cloned().collect();
            p.clear();
            out
        };
        for u in users {
            match tar_user(&self.store_root, &u).await {
                Some(tar) => {
                    if !self.sync_user(&u, tar).await {
                        self.mark_dirty(&u);
                    }
                }
                None => self.mark_dirty(&u),
            }
        }
    }

    /// Восстановление Maildir с телефона, если локальный стор пуст.
    pub async fn restore_if_empty(&self) -> bool {
        if !self.enabled {
            return false;
        }
        let root = self.store_root.clone();
        let empty = std::fs::read_dir(&root)
            .map(|mut it| it.next().is_none())
            .unwrap_or(true);
        if !empty {
            return false;
        }
        eprintln!("agent: local store empty, restoring from redmi...");
        let data = self
            .with_conn(|tx| {
                let (tx2, rx) = oneshot::channel();
                match tx.try_send(Req::Restore(tx2)) {
                    Ok(_) => Some(rx),
                    Err(_) => None,
                }
            })
            .await
            .flatten();
        match data {
            Some(d) if d.len() > 4 => {
                std::fs::create_dir_all(&root).ok();
                let mut child = match tokio::process::Command::new("tar")
                    .arg("-xf")
                    .arg("-")
                    .arg("-C")
                    .arg(&root)
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("agent: tar spawn: {e}");
                        return false;
                    }
                };
                if let Some(mut si) = child.stdin.take() {
                    si.write_all(&d).await.ok();
                }
                matches!(child.wait().await, Ok(s) if s.success())
            }
            _ => {
                eprintln!("agent: nothing to restore");
                false
            }
        }
    }
}

async fn tar_user(root: &PathBuf, user: &str) -> Option<Vec<u8>> {
    let safe = safe_component(user);
    let out = tokio::process::Command::new("tar")
        .arg("-cf")
        .arg("-")
        .arg("-C")
        .arg(root)
        .arg(&safe)
        .output()
        .await
        .ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

/// Слушатель агентских соединений (телефон сам подключается).
pub async fn agent_listener(ctx: Arc<crate::Ctx>) {
    let addr = match &ctx.cfg.agent_addr {
        Some(a) => a.clone(),
        None => return,
    };
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("agent: bind {addr}: {e}");
            return;
        }
    };
    eprintln!("agent: listening on {addr} (redmi dial-in)");
    loop {
        match listener.accept().await {
            Ok((sock, ip)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = agent_session(ctx, sock).await {
                        eprintln!("agent: {ip} session ended: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("agent: accept: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Чтение строки ответа (CRLF/LF) в String.
async fn read_reply_line<R: AsyncReadExt + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
) -> bool {
    buf.clear();
    loop {
        let mut ch = [0u8; 1];
        match rd.read(&mut ch).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => {
                buf.push(ch[0]);
                if ch[0] == b'\n' || buf.len() > 256 {
                    return true;
                }
            }
        }
    }
}

async fn agent_session(ctx: Arc<crate::Ctx>, mut sock: TcpStream) -> Result<(), String> {
    // авторизация: "AGENT <token>\n"
    let mut buf = vec![0u8; 256];
    let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&buf[..n]);
    if line.trim() != format!("AGENT {}", ctx.agent.token) {
        sock.write_all(b"AUTH ERR\n").await.ok();
        return Err("bad token".into());
    }
    sock.write_all(b"AGENT OK\n").await.ok();
    eprintln!("agent: redmi connected");

    let (req_tx, mut req_rx) = mpsc::channel::<Req>(64);
    {
        let mut conns = ctx.agent.conns.lock().await;
        conns.push(AgentConn { tx: req_tx.clone() });
    }
    {
        let hub = ctx.agent.clone();
        tokio::spawn(async move { hub.flush_pending().await });
    }

    let (mut rd, mut wr) = sock.into_split();
    let mut line_buf = Vec::new();

    loop {
        let req = tokio::select! {
            r = req_rx.recv() => match r {
                Some(r) => r,
                None => break,
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {
                if wr.write_all(b"PING\n").await.is_err() {
                    break;
                }
                continue;
            }
        };
        match req {
            Req::Score(text, reply) => {
                let mut res = None;
                let ok = wr
                    .write_all(format!("SCORE {}\n", text.len()).as_bytes())
                    .await
                    .is_ok()
                    && wr.write_all(text.as_bytes()).await.is_ok();
                if ok && read_reply_line(&mut rd, &mut line_buf).await {
                    let s = String::from_utf8_lossy(&line_buf);
                    if let Some(num) = s.trim().strip_prefix("SCORE ").and_then(|x| x.trim().parse().ok()) {
                        res = Some(num);
                    }
                }
                let _ = reply.send(res);
            }
            Req::Sync(user, tar, reply) => {
                let tar = if tar.is_empty() {
                    tar_user(&ctx.agent.store_root, &user).await.unwrap_or_default()
                } else {
                    tar
                };
                if tar.is_empty() {
                    let _ = reply.send(false);
                    continue;
                }
                let ok = wr
                    .write_all(format!("SYNC {} {}\n", user, tar.len()).as_bytes())
                    .await
                    .is_ok()
                    && wr.write_all(&tar).await.is_ok();
                let mut ok2 = false;
                if ok && read_reply_line(&mut rd, &mut line_buf).await {
                    ok2 = String::from_utf8_lossy(&line_buf).trim() == "SYNC OK";
                }
                if ok2 {
                    eprintln!("agent: synced {user} -> redmi");
                }
                let _ = reply.send(ok2);
            }
            Req::Restore(reply) => {
                let mut res = None;
                if wr.write_all(b"RESTORE\n").await.is_ok()
                    && read_reply_line(&mut rd, &mut line_buf).await
                {
                    let s = String::from_utf8_lossy(&line_buf);
                    let n: usize = s
                        .trim()
                        .strip_prefix("RESTORE ")
                        .and_then(|x| x.trim().parse().ok())
                        .unwrap_or(0);
                    if n > 0 && n < 2_000_000_000 {
                        let mut data = vec![0u8; n];
                        if rd.read_exact(&mut data).await.is_ok() {
                            res = Some(data);
                        }
                    }
                }
                let _ = reply.send(res);
            }
        }
    }
    // мёртвое соединение убираем
    let mut conns = ctx.agent.conns.lock().await;
    conns.retain(|c| !c.tx.same_channel(&req_tx));
    Err("closed".into())
}
