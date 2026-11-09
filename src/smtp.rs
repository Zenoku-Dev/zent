// smtp.rs — ESMTP-сервер: Inbound (25), Submission (587), Smtps (465 implicit TLS).
//  - enum Stream { Plain, Tls } с AsyncRead+AsyncWrite, STARTTLS-апгрейд со сбросом сессии
//  - PIPELINING / SIZE / 8BITMIME / STARTTLS / AUTH PLAIN LOGIN
//  - после DATA: Received, Received-SPF, Authentication-Results, DMARC, нейронный скоринг
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::spf::{self, SpfVerdict};
use crate::util::{b64_decode, hex, now, rfc2822, urandom};

const RD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_LINE: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpKind {
    Inbound,
    Submission,
    Smtps,
}

pub async fn smtp_listener(ctx: Arc<crate::Ctx>, addr: String, kind: SmtpKind) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("smtp: cannot bind {addr}: {e}");
            return;
        }
    };
    eprintln!("smtp: listening on {addr} ({kind:?})");
    loop {
        match listener.accept().await {
            Ok((sock, peer)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move { handle_conn(ctx, sock, peer, kind).await });
            }
            Err(e) => {
                eprintln!("smtp: accept {addr}: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

// --- стрим ---

enum Stream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
    Taken,
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s).poll_flush(cx),
            Stream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Taken => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "taken"))),
        }
    }
}

/// Буферизованный коннекшен: строки команд + DATA до "\r\n.\r\n".
struct Conn {
    inner: Stream,
    rbuf: Vec<u8>,
    rpos: usize,
}

impl Conn {
    fn new(inner: Stream) -> Conn {
        Conn {
            inner,
            rbuf: Vec::with_capacity(8192),
            rpos: 0,
        }
    }

    async fn send(&mut self, s: &str) {
        if self.inner.write_all(s.as_bytes()).await.is_ok() {
            let _ = self.inner.flush().await;
        }
    }

    async fn fill(&mut self) -> io::Result<()> {
        if self.rpos >= self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        }
        let mut chunk = [0u8; 8192];
        let n = tokio::time::timeout(RD_TIMEOUT, self.inner.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timeout"))??;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        }
        self.rbuf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    async fn read_line(&mut self) -> io::Result<String> {
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
                if line.len() > MAX_LINE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
            }
            self.fill().await?;
        }
    }

    /// DATA: читает до "\r\n.\r\n", снимает dot-stuffing, лимит max_message.
    async fn read_data(&mut self, max: u64) -> Result<Vec<u8>, DataErr> {
        // виртуальный ведущий CRLF: пустое письмо = сразу ".\r\n"
        let mut acc: Vec<u8> = b"\r\n".to_vec();
        let mut search_from = 0usize;
        loop {
            if let Some(idx) = find_terminator(&acc, search_from) {
                let leftover = acc.split_off(idx + 5);
                let data = acc[2..idx].to_vec();
                self.rbuf = leftover;
                self.rpos = 0;
                return Ok(unstuff(&data));
            }
            search_from = acc.len().saturating_sub(4);
            if self.rpos >= self.rbuf.len() {
                if let Err(e) = self.fill().await {
                    return Err(DataErr::Io(e));
                }
            }
            acc.extend_from_slice(&self.rbuf[self.rpos..]);
            self.rpos = self.rbuf.len();
            if acc.len() as u64 > max + 8192 {
                return Err(DataErr::TooBig);
            }
        }
    }
}

enum DataErr {
    Io(io::Error),
    TooBig,
}

fn find_terminator(buf: &[u8], from: usize) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    (from..=buf.len() - 5).find(|&i| &buf[i..i + 5] == b"\r\n.\r\n")
}

fn unstuff(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len());
    let mut at_start = true;
    let mut i = 0usize;
    while i < d.len() {
        let skip = at_start && d[i] == b'.';
        if skip {
            i += 1; // снимаем stuffing
            if i >= d.len() {
                break;
            }
        }
        let b = d[i];
        out.push(b);
        at_start = b == b'\n';
        i += 1;
    }
    out
}

// --- сессия ---

struct Session {
    kind: SmtpKind,
    peer: SocketAddr,
    helo: String,
    authed: Option<String>,
    mail_from: Option<String>,
    rcpts: Vec<String>,
}

async fn handle_conn(ctx: Arc<crate::Ctx>, sock: TcpStream, peer: SocketAddr, kind: SmtpKind) {
    let _ = sock.set_nodelay(true);
    let mut stream = if kind == SmtpKind::Smtps {
        match &ctx.acceptor {
            Some(a) => match a.accept(sock).await {
                Ok(s) => Stream::Tls(s),
                Err(e) => {
                    eprintln!("smtp: tls handshake {peer}: {e}");
                    return;
                }
            },
            None => {
                eprintln!("smtp: smtps without TLS config, dropping {peer}");
                return;
            }
        }
    } else {
        Stream::Plain(sock)
    };
    let mut greet = true;
    loop {
        let mut conn = Conn::new(stream);
        if greet {
            conn.send(&format!("220 {} ESMTP zent\r\n", ctx.cfg.hostname)).await;
            greet = false;
        }
        let mut sess = Session {
            kind,
            peer,
            helo: String::new(),
            authed: None,
            mail_from: None,
            rcpts: Vec::new(),
        };
        match run_session(&ctx, &mut conn, &mut sess).await {
            Ctrl::Close => return,
            Ctrl::StartTLS(s) => stream = s, // состояние сброшено: новый Session, EHLO заново
        }
    }
}

enum Ctrl {
    Close,
    StartTLS(Stream),
}

fn parse_path(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if let Some(lt) = s.find('<') {
        let after = &s[lt + 1..];
        let gt = after.find('>')?;
        Some((after[..gt].trim().to_string(), after[gt + 1..].trim().to_string()))
    } else {
        let mut it = s.split_whitespace();
        let addr = it.next()?.trim_matches('<').trim_end_matches('>').to_string();
        Some((addr, it.collect::<Vec<_>>().join(" ")))
    }
}

fn local_rcpt(ctx: &crate::Ctx, addr: &str) -> bool {
    match addr.rsplit_once('@') {
        Some((_, d)) => ctx.cfg.is_local_domain(d),
        None => false,
    }
}

async fn run_session(ctx: &Arc<crate::Ctx>, conn: &mut Conn, sess: &mut Session) -> Ctrl {
    loop {
        let line = match conn.read_line().await {
            Ok(l) => l,
            Err(_) => return Ctrl::Close,
        };
        let (cmd, arg) = match line.split_once(' ') {
            Some((c, a)) => (c.to_ascii_uppercase(), a.trim().to_string()),
            None => (line.to_ascii_uppercase(), String::new()),
        };
        match cmd.as_str() {
            "HELO" => {
                if arg.is_empty() {
                    conn.send("501 5.5.4 Syntax: HELO hostname\r\n").await;
                    continue;
                }
                sess.helo = arg;
                conn.send(&format!("250 {}\r\n", ctx.cfg.hostname)).await;
            }
            "EHLO" => {
                if arg.is_empty() {
                    conn.send("501 5.5.4 Syntax: EHLO hostname\r\n").await;
                    continue;
                }
                sess.helo = arg;
                let mut caps = vec![
                    format!("250-{}", ctx.cfg.hostname),
                    "250-PIPELINING".to_string(),
                    format!("250-SIZE {}", ctx.cfg.max_message),
                    "250-8BITMIME".to_string(),
                ];
                if sess.kind != SmtpKind::Smtps && ctx.acceptor.is_some() {
                    caps.push("250-STARTTLS".to_string());
                }
                caps.push("250-AUTH PLAIN LOGIN".to_string());
                // последняя строка ответа — "250 " с пробелом (RFC 5321)
                let last = caps.len() - 1;
                caps[last] = format!("250 {}", &caps[last][4..]);
                conn.send(&format!("{}\r\n", caps.join("\r\n"))).await;
            }
            "STARTTLS" => {
                if sess.kind == SmtpKind::Smtps || matches!(conn.inner, Stream::Tls(_)) {
                    conn.send("503 5.5.1 TLS already active\r\n").await;
                    continue;
                }
                let acceptor = match &ctx.acceptor {
                    Some(a) => a.clone(),
                    None => {
                        conn.send("503 5.5.1 TLS not available\r\n").await;
                        continue;
                    }
                };
                conn.send("220 2.0.0 Ready to start TLS\r\n").await;
                let tcp = match std::mem::replace(&mut conn.inner, Stream::Taken) {
                    Stream::Plain(s) => s,
                    other => {
                        conn.inner = other;
                        continue;
                    }
                };
                return match acceptor.accept(tcp).await {
                    Ok(t) => Ctrl::StartTLS(Stream::Tls(t)),
                    Err(e) => {
                        eprintln!("smtp: STARTTLS {}: {e}", sess.peer);
                        Ctrl::Close
                    }
                };
            }
            "AUTH" => {
                if sess.authed.is_some() {
                    conn.send("503 5.5.1 Already authenticated\r\n").await;
                    continue;
                }
                let mut it = arg.split_whitespace();
                let mech = it.next().unwrap_or("").to_ascii_uppercase();
                let creds = match mech.as_str() {
                    "PLAIN" => {
                        let resp = match it.next() {
                            Some(r) => r.to_string(),
                            None => {
                                conn.send("334 \r\n").await;
                                match conn.read_line().await {
                                    Ok(l) => l,
                                    Err(_) => return Ctrl::Close,
                                }
                            }
                        };
                        if resp.trim() == "*" {
                            conn.send("501 5.7.0 Authentication cancelled\r\n").await;
                            continue;
                        }
                        match b64_decode(resp.trim()) {
                            Some(raw) => {
                                let parts: Vec<Vec<u8>> = raw.split(|&b| b == 0).map(|p| p.to_vec()).collect();
                                if parts.len() != 3 {
                                    conn.send("501 5.5.2 Invalid AUTH PLAIN\r\n").await;
                                    continue;
                                }
                                Some((
                                    String::from_utf8_lossy(&parts[1]).into_owned(),
                                    String::from_utf8_lossy(&parts[2]).into_owned(),
                                ))
                            }
                            None => None,
                        }
                    }
                    "LOGIN" => {
                        conn.send("334 VXNlcm5hbWU6\r\n").await;
                        let l = match conn.read_line().await {
                            Ok(x) => x,
                            Err(_) => return Ctrl::Close,
                        };
                        if l.trim() == "*" {
                            conn.send("501 5.7.0 Authentication cancelled\r\n").await;
                            continue;
                        }
                        conn.send("334 UGFzc3dvcmQ6\r\n").await;
                        let p = match conn.read_line().await {
                            Ok(x) => x,
                            Err(_) => return Ctrl::Close,
                        };
                        match (b64_decode(l.trim()), b64_decode(p.trim())) {
                            (Some(a), Some(b)) => Some((
                                String::from_utf8_lossy(&a).into_owned(),
                                String::from_utf8_lossy(&b).into_owned(),
                            )),
                            _ => None,
                        }
                    }
                    _ => {
                        conn.send("504 5.5.4 Unsupported authentication mechanism\r\n").await;
                        continue;
                    }
                };
                let (login, pass) = match creds {
                    Some(c) => c,
                    None => {
                        conn.send("501 5.5.2 Invalid base64 data\r\n").await;
                        continue;
                    }
                };
                let user = ctx
                    .users
                    .read()
                    .await
                    .verify(&login, &pass, ctx.cfg.domains.first().map(|s| s.as_str()));
                match user {
                    Some(u) => {
                        sess.authed = Some(u.email);
                        conn.send("235 2.7.0 Authentication successful\r\n").await;
                    }
                    None => {
                        conn.send("535 5.7.8 Authentication credentials invalid\r\n").await;
                    }
                }
            }
            "MAIL" => {
                if sess.helo.is_empty() {
                    conn.send("503 5.5.1 Error: send HELO/EHLO first\r\n").await;
                    continue;
                }
                if !arg.to_ascii_uppercase().starts_with("FROM:") {
                    conn.send("501 5.5.4 Syntax: MAIL FROM:<address>\r\n").await;
                    continue;
                }
                let (addr, params) = match parse_path(&arg[5..]) {
                    Some(p) => p,
                    None => {
                        conn.send("501 5.5.4 Syntax: MAIL FROM:<address>\r\n").await;
                        continue;
                    }
                };
                for p in params.split_whitespace() {
                    if let Some(v) = p.to_ascii_uppercase().strip_prefix("SIZE=") {
                        if let Ok(sz) = v.parse::<u64>() {
                            if sz > ctx.cfg.max_message {
                                conn.send("552 5.3.4 Message size exceeds fixed maximum message size\r\n").await;
                                continue;
                            }
                        }
                    }
                }
                sess.mail_from = Some(addr);
                sess.rcpts.clear();
                conn.send("250 2.1.0 Ok\r\n").await;
            }
            "RCPT" => {
                if sess.mail_from.is_none() {
                    conn.send("503 5.5.1 Error: need MAIL command first\r\n").await;
                    continue;
                }
                if !arg.to_ascii_uppercase().starts_with("TO:") {
                    conn.send("501 5.5.4 Syntax: RCPT TO:<address>\r\n").await;
                    continue;
                }
                let (addr, _) = match parse_path(&arg[3..]) {
                    Some(p) => p,
                    None => {
                        conn.send("501 5.5.4 Syntax: RCPT TO:<address>\r\n").await;
                        continue;
                    }
                };
                if !addr.contains('@') {
                    conn.send("501 5.1.3 Bad recipient address\r\n").await;
                    continue;
                }
                match sess.kind {
                    SmtpKind::Inbound => {
                        let email = addr.to_lowercase();
                        let ok = ctx.cfg.is_local_domain(email.rsplit_once('@').unwrap().1)
                            && ctx.users.read().await.exists(&email);
                        if !ok {
                            conn.send(&format!("550 5.1.1 <{addr}>: Recipient address rejected: User unknown\r\n")).await;
                            continue;
                        }
                    }
                    _ => {
                        if sess.authed.is_none() {
                            conn.send("530 5.7.0 Authentication required\r\n").await;
                            continue;
                        }
                    }
                }
                sess.rcpts.push(addr);
                conn.send("250 2.1.5 Ok\r\n").await;
            }
            "DATA" => {
                if sess.rcpts.is_empty() {
                    conn.send("503 5.5.1 Error: need RCPT command first\r\n").await;
                    continue;
                }
                conn.send("354 End data with <CR><LF>.<CR><LF>\r\n").await;
                match conn.read_data(ctx.cfg.max_message).await {
                    Ok(data) => {
                        let resp = finish_message(ctx, sess, &data).await;
                        sess.mail_from = None;
                        sess.rcpts.clear();
                        conn.send(&resp).await;
                    }
                    Err(DataErr::TooBig) => {
                        sess.mail_from = None;
                        sess.rcpts.clear();
                        conn.send("552 5.3.4 Message size exceeds fixed maximum message size\r\n").await;
                    }
                    Err(DataErr::Io(_)) => return Ctrl::Close,
                }
            }
            "RSET" => {
                sess.mail_from = None;
                sess.rcpts.clear();
                conn.send("250 2.0.0 Ok\r\n").await;
            }
            "NOOP" => {
                conn.send("250 2.0.0 Ok\r\n").await;
            }
            "QUIT" => {
                conn.send("221 2.0.0 Bye\r\n").await;
                return Ctrl::Close;
            }
            "VRFY" => {
                conn.send("252 2.1.5 Cannot VRFY user, but will accept message and attempt delivery\r\n").await;
            }
            _ => {
                conn.send("500 5.5.2 Error: command not recognized\r\n").await;
            }
        }
    }
}

/// Финализация: Received (+SPF/DKIM/DMARC для Inbound), нейронный скоринг, доставка.
async fn finish_message(ctx: &crate::Ctx, sess: &Session, data: &[u8]) -> String {
    let hostname = ctx.cfg.hostname.as_str();
    let ip = sess.peer.ip();
    let from = sess.mail_from.clone().unwrap_or_default();
    let id = hex(&urandom(6));
    let mut out = format!(
        "Received: from {} ({})\r\n\tby {} with ESMTP id {};\r\n\t{}\r\n",
        sess.helo,
        ip,
        hostname,
        id,
        rfc2822(now())
    );
    let mut score: Option<f64> = None;
    if sess.kind == SmtpKind::Inbound {
        let (verdict, spf_dom) = spf::check(ip, &sess.helo, &from).await;
        out.push_str(&format!(
            "Received-SPF: {} ({}) client-ip={};\r\n",
            verdict.as_str(),
            spf_dom,
            ip
        ));
        let dres = crate::dkim::verify_all(data).await;
        let dkim_passed = dres.iter().any(|r| r.passed);
        let parts: Vec<String> = if dres.is_empty() {
            vec!["dkim=none".to_string()]
        } else {
            dres.iter()
                .map(|r| format!("dkim={} header.d={}", if r.passed { "pass" } else { "fail" }, r.domain))
                .collect()
        };
        out.push_str(&format!(
            "Authentication-Results: {}; spf={}; {}\r\n",
            hostname,
            verdict.as_str(),
            parts.join("; ")
        ));
        // DMARC: p=reject и провалены оба механизма -> отказ
        let from_dom = from.rsplit_once('@').map(|(_, d)| d.to_lowercase()).unwrap_or_default();
        if !from_dom.is_empty() {
            if let Some(p) = dmarc_policy(&from_dom).await {
                if p == "reject" && ctx.cfg.dmarc_reject && verdict != SpfVerdict::Pass && !dkim_passed {
                    return "550 5.7.1 rejected by DMARC\r\n".to_string();
                }
            }
        }
        // нейронный скоринг (None — redmi офлайн, fail-open)
        score = ctx.agent.score(&crate::mime::Msg::parse(data).extract_text()).await;
    }
    if let Some(s) = score {
        out.push_str(&format!("X-Zent-Spam-Score: {s}\r\n"));
        out.push_str(&format!(
            "X-Zent-Spam: {}\r\n",
            if s >= ctx.cfg.ml_threshold { "yes" } else { "no" }
        ));
    }
    let spam = score.map(|s| s >= ctx.cfg.ml_threshold).unwrap_or(false);
    let mut final_bytes = out.into_bytes();
    final_bytes.extend_from_slice(data);
    // доставка
    for rcpt in &sess.rcpts {
        if !local_rcpt(ctx, rcpt) {
            continue;
        }
        let folder = if spam {
            let _ = ctx.store.create_folder(rcpt, "Junk");
            "Junk"
        } else {
            ""
        };
        match ctx.store.deliver(rcpt, &final_bytes, folder) {
            Ok(_) => ctx.agent.mark_dirty(rcpt),
            Err(e) => eprintln!("smtp: deliver to {rcpt}: {e}"),
        }
    }
    let remote: Vec<String> = sess.rcpts.iter().filter(|r| !local_rcpt(ctx, r)).cloned().collect();
    if !remote.is_empty() {
        ctx.queue.enqueue(&from, &remote, &final_bytes).await;
    }
    format!("250 2.0.0 Ok: queued as {id}\r\n")
}

async fn dmarc_policy(domain: &str) -> Option<String> {
    let name = format!("_dmarc.{domain}");
    let recs = tokio::task::spawn_blocking(move || crate::dns::txt_lookup(&name))
        .await
        .unwrap_or_default();
    for r in recs {
        let rl = r.trim().to_ascii_lowercase();
        if rl.starts_with("v=dmarc1") {
            for t in rl.split(';') {
                let t = t.trim();
                if let Some(v) = t.strip_prefix("p=") {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}
