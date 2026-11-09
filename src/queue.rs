// queue.rs — спул исходящей почты и доставщик.
//  - <id>.meta ("from ...", "rcpt ...", "attempt <n> <ts>") + <id>.eml, запись tmp+rename
//  - backoff: last + min(attempt^2*60, 3600); attempt>=96 -> bounce (DSN в ящик)
//  - relay_host задан -> прямой connect; иначе MX-lookup и connect :25
//  - STARTTLS с no-verify верификатором (OnceLock, строится один раз)
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::util::{b64_encode, hex, now, rfc2822, urandom};

const MAX_ATTEMPTS: u32 = 96;

pub struct Queue {
    pub dir: std::path::PathBuf,
}

struct QMsg {
    id: String,
    from: String,
    rcpts: Vec<String>,
    attempt: u32,
    ts: u64,
}

impl Queue {
    pub fn new(cfg: &Config) -> Queue {
        Queue { dir: cfg.queue.clone() }
    }

    pub async fn enqueue(&self, from: &str, rcpts: &[String], raw: &[u8]) {
        if rcpts.is_empty() {
            return;
        }
        let _ = std::fs::create_dir_all(&self.dir);
        let id = hex(&urandom(8));
        let mut meta = format!("from {from}\n");
        for r in rcpts {
            meta.push_str(&format!("rcpt {r}\n"));
        }
        meta.push_str(&format!("attempt 0 {}\n", now()));
        let tmp_e = self.dir.join(format!(".tmp-{id}.eml"));
        let tmp_m = self.dir.join(format!(".tmp-{id}.meta"));
        if std::fs::write(&tmp_e, raw).and_then(|_| std::fs::write(&tmp_m, meta)).is_err() {
            return;
        }
        let _ = std::fs::rename(&tmp_e, self.dir.join(format!("{id}.eml")));
        let _ = std::fs::rename(&tmp_m, self.dir.join(format!("{id}.meta")));
    }

    fn pending(&self) -> Vec<QMsg> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(_) => return out,
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_suffix(".meta")
                    .map(|s| s.to_string())
            })
            .collect();
        ids.sort();
        for id in ids {
            if !self.dir.join(format!("{id}.eml")).exists() {
                continue;
            }
            let raw = match std::fs::read_to_string(self.dir.join(format!("{id}.meta"))) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut from = String::new();
            let mut rcpts = Vec::new();
            let mut attempt = 0u32;
            let mut ts = 0u64;
            for line in raw.lines() {
                if let Some(v) = line.strip_prefix("from ") {
                    from = v.to_string();
                } else if let Some(v) = line.strip_prefix("rcpt ") {
                    rcpts.push(v.to_string());
                } else if let Some(v) = line.strip_prefix("attempt ") {
                    let mut it = v.split_whitespace();
                    attempt = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                    ts = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                }
            }
            out.push(QMsg { id, from, rcpts, attempt, ts });
        }
        out
    }

    pub fn list(&self) {
        for m in self.pending() {
            println!(
                "{}\tfrom {}\tattempt {}\trcpts: {}",
                m.id,
                m.from,
                m.attempt,
                m.rcpts.join(",")
            );
        }
    }
}

fn write_meta(q: &Queue, id: &str, from: &str, rcpts: &[String], attempt: u32, ts: u64) {
    let mut s = format!("from {from}\n");
    for r in rcpts {
        s.push_str(&format!("rcpt {r}\n"));
    }
    s.push_str(&format!("attempt {attempt} {ts}\n"));
    let tmp = q.dir.join(format!(".tmp-{id}.meta"));
    if std::fs::write(&tmp, s).is_ok() {
        let _ = std::fs::rename(&tmp, q.dir.join(format!("{id}.meta")));
    }
}

fn remove_msg(q: &Queue, id: &str) {
    let _ = std::fs::remove_file(q.dir.join(format!("{id}.meta")));
    let _ = std::fs::remove_file(q.dir.join(format!("{id}.eml")));
}

pub async fn queue_loop(q: Arc<Queue>, store: crate::maildir::Store, hostname: String, relay_host: Option<String>, relay_port: u16) {
    loop {
        queue_loop_once(q.clone(), store.clone(), hostname.clone(), relay_host.clone(), relay_port).await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}

pub async fn queue_loop_once(q: Arc<Queue>, store: crate::maildir::Store, hostname: String, relay_host: Option<String>, relay_port: u16) {
    // relay_user/relay_pass в сигнатуре нет — берём из конфига (как сервер запущен)
    let auth: Option<(String, String)> = (|| {
        let cfg = Config::load("/etc/zent/zent.conf")
            .ok()
            .or_else(|| Config::load("zent.conf").ok())?;
        let u = cfg.relay_user?;
        let p = cfg.relay_pass?;
        Some((u, p))
    })();
    for msg in q.pending() {
        let t = now();
        let delay = (msg.attempt as u64 * msg.attempt as u64 * 60).min(3600);
        if t < msg.ts.saturating_add(delay) {
            continue;
        }
        if msg.attempt >= MAX_ATTEMPTS {
            bounce(&store, &hostname, &msg);
            remove_msg(&q, &msg.id);
            continue;
        }
        let raw = match std::fs::read(q.dir.join(format!("{}.eml", msg.id))) {
            Ok(r) => r,
            Err(_) => continue,
        };
        // группируем rcpt по доменам
        let mut bydom: HashMap<String, Vec<String>> = HashMap::new();
        for r in &msg.rcpts {
            let dom = r.rsplit_once('@').map(|(_, d)| d.trim().to_lowercase()).unwrap_or_default();
            bydom.entry(dom).or_default().push(r.clone());
        }
        let mut delivered: Vec<String> = Vec::new();
        for (dom, rcpts) in &bydom {
            let (hosts, port) = if let Some(h) = &relay_host {
                (vec![h.clone()], relay_port)
            } else {
                let d = dom.clone();
                (
                    tokio::task::spawn_blocking(move || crate::dns::mx_lookup(&d))
                        .await
                        .unwrap_or_default(),
                    25,
                )
            };
            for host in &hosts {
                match smtp_deliver(host, port, &hostname, auth.as_ref(), &msg.from, rcpts, &raw).await {
                    Ok(ok) => {
                        delivered.extend(ok);
                        break;
                    }
                    Err(e) => eprintln!("queue: {} via {host}:{port}: {e}", msg.id),
                }
            }
        }
        let remaining: Vec<String> = msg.rcpts.iter().filter(|r| !delivered.contains(r)).cloned().collect();
        if remaining.is_empty() {
            remove_msg(&q, &msg.id);
        } else {
            write_meta(&q, &msg.id, &msg.from, &remaining, msg.attempt + 1, now());
        }
    }
}

fn bounce(store: &crate::maildir::Store, hostname: &str, msg: &QMsg) {
    let list = msg
        .rcpts
        .iter()
        .map(|r| format!("  {r}"))
        .collect::<Vec<_>>()
        .join("\r\n");
    let dsn = format!(
        "From: postmaster@{hostname}\r\nTo: {}\r\nSubject: Undelivered Mail\r\nDate: {}\r\n\r\n\
         Delivery to the following recipient(s) permanently failed after {} attempts:\r\n\
         \r\n\
         {list}\r\n\
         \r\n\
         The message was returned to the queue sender.\r\n\
         \r\n\
         -- zent mail queue\r\n",
        msg.from,
        rfc2822(now()),
        msg.attempt
    );
    if store.exists(&msg.from) {
        let _ = store.deliver(&msg.from, dsn.as_bytes(), "");
    }
}

// --- SMTP-клиент ---

enum CStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    Taken,
}

impl AsyncRead for CStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            CStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            CStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            CStream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
}

impl AsyncWrite for CStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            CStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            CStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            CStream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            CStream::Plain(s) => Pin::new(s).poll_flush(cx),
            CStream::Tls(s) => Pin::new(s).poll_flush(cx),
            CStream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            CStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            CStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            CStream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
}

/// Верификатор "trust anything" — MX/relay у нас без PKI.
fn client_cfg() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        #[derive(Debug)]
        struct NoVerify;

        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }

        Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        )
    })
    .clone()
}

struct ClientConn {
    s: CStream,
    rbuf: Vec<u8>,
    rpos: usize,
}

impl ClientConn {
    fn new(s: CStream) -> ClientConn {
        ClientConn {
            s,
            rbuf: Vec::with_capacity(8192),
            rpos: 0,
        }
    }

    async fn line(&mut self) -> Result<String, String> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            while self.rpos < self.rbuf.len() {
                let b = self.rbuf[self.rpos];
                self.rpos += 1;
                if b == b'\n' {
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(String::from_utf8_lossy(&line).into_owned());
                }
                line.push(b);
                if line.len() > 4096 {
                    return Err("line too long".into());
                }
            }
            if self.rpos >= self.rbuf.len() {
                self.rbuf.clear();
                self.rpos = 0;
            }
            let mut chunk = [0u8; 8192];
            let n = self.s.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed by peer".into());
            }
            self.rbuf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn reply(&mut self) -> Result<(u16, String), String> {
        let mut text = String::new();
        loop {
            let l = self.line().await?;
            if l.len() < 4 {
                return Err(format!("bad reply line: {l}"));
            }
            let code: u16 = l[..3].parse().map_err(|_| format!("bad reply code: {l}"))?;
            let cont = l.as_bytes()[3] == b'-';
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&l[4..]);
            if !cont {
                return Ok((code, text));
            }
        }
    }

    async fn cmd(&mut self, s: &str) -> Result<(u16, String), String> {
        self.s
            .write_all(format!("{s}\r\n").as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let _ = self.s.flush().await;
        self.reply().await
    }
}

/// dot-stuffing перед отправкой DATA + терминатор ".\r\n"
fn stuff(raw: &[u8]) -> Vec<u8> {
    if raw.is_empty() {
        // пустое DATA — только терминатор
        return b".\r\n".to_vec();
    }
    let mut out = Vec::with_capacity(raw.len() + 16);
    let mut at_start = true;
    for &b in raw {
        if at_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_start = b == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Полная SMTP-транзакция; возвращает список успешно принятых rcpt (после DATA 250).
async fn smtp_deliver(
    host: &str,
    port: u16,
    hostname: &str,
    auth: Option<&(String, String)>,
    from: &str,
    rcpts: &[String],
    raw: &[u8],
) -> Result<Vec<String>, String> {
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let sock = TcpStream::connect(&addr).await.map_err(|e| format!("connect: {e}"))?;
    let _ = sock.set_nodelay(true);
    let mut c = ClientConn::new(CStream::Plain(sock));
    let (code, _) = c.reply().await?;
    if code != 220 {
        return Err(format!("greeting {code}"));
    }
    let (code, caps) = c.cmd(&format!("EHLO {hostname}")).await?;
    if code != 250 {
        return Err(format!("EHLO -> {code}"));
    }
    // STARTTLS, если предложен
    if caps
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case("starttls"))
    {
        let (code, _) = c.cmd("STARTTLS").await?;
        if code == 220 {
            let tcp = match std::mem::replace(&mut c.s, CStream::Taken) {
                CStream::Plain(s) => s,
                _ => return Err("stream taken".into()),
            };
            let name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|_| format!("bad server name: {host}"))?;
            let tls = tokio_rustls::TlsConnector::from(client_cfg())
                .connect(name, tcp)
                .await
                .map_err(|e| format!("tls: {e}"))?;
            c.s = CStream::Tls(tls);
            let (code, _) = c.cmd(&format!("EHLO {hostname}")).await?;
            if code != 250 {
                return Err(format!("EHLO after TLS -> {code}"));
            }
        }
    }
    if let Some((u, p)) = auth {
        let tok = b64_encode(format!("\0{u}\0{p}").as_bytes());
        let (code, _) = c.cmd(&format!("AUTH PLAIN {tok}")).await?;
        if code != 235 {
            return Err(format!("AUTH -> {code}"));
        }
    }
    let (code, _) = c.cmd(&format!("MAIL FROM:<{from}>")).await?;
    if code != 250 {
        return Err(format!("MAIL -> {code}"));
    }
    let mut ok = Vec::new();
    for r in rcpts {
        let (code, _) = c.cmd(&format!("RCPT TO:<{r}>")).await?;
        if code == 250 || code == 251 {
            ok.push(r.clone());
        }
    }
    if ok.is_empty() {
        let _ = c.cmd("QUIT").await;
        return Err("no recipients accepted".into());
    }
    let (code, _) = c.cmd("DATA").await?;
    if code != 354 {
        return Err(format!("DATA -> {code}"));
    }
    c.s
        .write_all(&stuff(raw))
        .await
        .map_err(|e| format!("write data: {e}"))?;
    let _ = c.s.flush().await;
    let (code, _) = c.reply().await?;
    if code != 250 {
        return Err(format!("end of DATA -> {code}"));
    }
    let _ = c.cmd("QUIT").await;
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_stuffing() {
        assert_eq!(stuff(b"hi\r\n"), b"hi\r\n.\r\n");
        assert_eq!(stuff(b".hidden\r\n"), b"..hidden\r\n.\r\n");
        assert_eq!(stuff(b"no-newline"), b"no-newline\r\n.\r\n");
        assert_eq!(stuff(b""), b".\r\n");
    }

    #[test]
    fn meta_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("zent-q-{}", hex(&urandom(4))));
        let q = Queue { dir: tmp.clone() };
        std::fs::create_dir_all(&tmp).unwrap();
        // enqueue async — под тастом
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(q.enqueue("a@b.c", &["x@y.z".into()], b"hello\r\n"));
        let p = q.pending();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].from, "a@b.c");
        assert_eq!(p[0].rcpts, vec!["x@y.z".to_string()]);
        assert_eq!(p[0].attempt, 0);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
