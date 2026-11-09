// pop3.rs — POP3-сервер: USER/PASS, TLS (implicit + STLS), STAT/LIST/UIDL/RETR/TOP/DELE/RSET.
// Снапшот maildrop'а делается один раз при логине и не меняется до QUIT (RFC 1939).
use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::maildir::MsgMeta;
use crate::Ctx;

const LINE_MAX: usize = 512;
const CMD_TIMEOUT: u64 = 600; // 10 минут на команду

// --- поток: plain TCP или TLS ---
enum Stream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Буферизованный ввод/вывод поверх Stream (свой буфер, чтобы легко апгрейдить TLS).
struct Io {
    s: Stream,
    buf: Vec<u8>,
    pos: usize,
}

impl Io {
    fn new(s: Stream) -> Io {
        Io { s, buf: Vec::with_capacity(8192), pos: 0 }
    }

    async fn read_more(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 8192];
        let n = self.s.read(&mut tmp).await?;
        if n > 0 {
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(n)
    }

    /// Строка без CRLF. None = чистый EOF.
    async fn read_line(&mut self, max: usize) -> io::Result<Option<String>> {
        loop {
            if let Some(i) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let end = self.pos + i;
                let mut l = &self.buf[self.pos..end];
                if l.last() == Some(&b'\r') {
                    l = &l[..l.len() - 1];
                }
                self.pos = end + 1;
                if l.len() > max {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                return Ok(Some(String::from_utf8_lossy(l).to_string()));
            }
            if self.buf.len() - self.pos > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            if self.read_more().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid-line"))
                };
            }
        }
    }

    fn take_plain(self) -> Option<TcpStream> {
        match self.s {
            Stream::Plain(t) => Some(t),
            Stream::Tls(_) => None,
        }
    }

    async fn write_all(&mut self, b: &[u8]) -> io::Result<()> {
        self.s.write_all(b).await?;
        self.s.flush().await
    }
}

async fn send(io: &mut Io, s: &str) {
    let mut b = s.as_bytes().to_vec();
    b.extend_from_slice(b"\r\n");
    let _ = io.write_all(&b).await;
}

async fn read_line_to(io: &mut Io) -> io::Result<Option<String>> {
    match tokio::time::timeout(Duration::from_secs(CMD_TIMEOUT), io.read_line(LINE_MAX)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "pop3 timeout")),
    }
}

// --- утилиты сообщений ---

/// dot-stuffing + завершающая точка: ".x" -> "..x", в конце "\r\n.\r\n"
fn dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut at_line_start = true;
    for &b in data {
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = b == b'\n';
    }
    if !out.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Граница заголовок/тело: индекс конца пустой строки (включая её).
fn header_end(data: &[u8]) -> usize {
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == b'\n' {
            if data[i + 1] == b'\n' {
                return i + 2;
            }
            if i + 2 < data.len() && data[i + 1] == b'\r' && data[i + 2] == b'\n' {
                return i + 3;
            }
        }
        i += 1;
    }
    data.len()
}

/// TOP: заголовки целиком + первые k строк тела.
fn top_of(data: &[u8], k: usize) -> Vec<u8> {
    let hend = header_end(data);
    let mut out = data[..hend].to_vec();
    let body = &data[hend..];
    let mut pos = 0;
    let mut cnt = 0;
    while pos < body.len() && cnt < k {
        let eol = body[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(body.len());
        out.extend_from_slice(&body[pos..eol]);
        pos = eol;
        cnt += 1;
    }
    if !out.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

// --- слушатель ---

pub async fn pop3_listener(ctx: Arc<Ctx>, addr: String, implicit_tls: bool) {
    match TcpListener::bind(&addr).await {
        Ok(l) => loop {
            match l.accept().await {
                Ok((tcp, _peer)) => {
                    let c = ctx.clone();
                    tokio::spawn(handle_conn(c, tcp, implicit_tls));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        },
        Err(e) => eprintln!("pop3: bind {addr}: {e}"),
    }
}

async fn handle_conn(ctx: Arc<Ctx>, tcp: TcpStream, implicit_tls: bool) {
    let io = if implicit_tls {
        let Some(acc) = ctx.acceptor.clone() else { return };
        match acc.accept(tcp).await {
            Ok(t) => Io::new(Stream::Tls(t)),
            Err(_) => return,
        }
    } else {
        Io::new(Stream::Plain(tcp))
    };
    run_session(ctx, io, implicit_tls).await;
}

async fn run_session(ctx: Arc<Ctx>, mut io: Io, mut implicit_tls: bool) {
    send(&mut io, "+OK zent POP3 ready").await;
    let mut pending_user: Option<String> = None;
    let mut email: Option<String> = None;
    let mut msgs: Vec<MsgMeta> = Vec::new();
    let mut deleted: HashSet<usize> = HashSet::new(); // 1-based номера

    loop {
        let line = match read_line_to(&mut io).await {
            Ok(Some(l)) => l,
            _ => return,
        };
        let (cmd, arg) = match line.trim().split_once(' ') {
            Some((a, b)) => (a, b.trim()),
            None => (line.trim(), ""),
        };
        let cu = cmd.to_ascii_uppercase();

        match cu.as_str() {
            "CAPA" => {
                let mut out = String::from("+OK Capability list follows");
                out.push_str("\r\nUSER\r\nTOP\r\nUIDL\r\nPIPELINING");
                if ctx.acceptor.is_some() && !implicit_tls && email.is_none() {
                    out.push_str("\r\nSTLS");
                }
                out.push_str("\r\nIMPLEMENTATION zent\r\n.");
                send(&mut io, &out).await;
            }
            "USER" => {
                if email.is_some() {
                    send(&mut io, "-ERR already authenticated").await;
                } else if arg.is_empty() {
                    send(&mut io, "-ERR missing username").await;
                } else {
                    pending_user = Some(arg.to_string());
                    send(&mut io, "+OK user accepted").await;
                }
            }
            "PASS" => {
                if email.is_some() {
                    send(&mut io, "-ERR already authenticated").await;
                    continue;
                }
                let Some(u) = pending_user.clone() else {
                    send(&mut io, "-ERR USER first").await;
                    continue;
                };
                let verified = {
                    let db = ctx.users.read().await;
                    db.verify(&u, arg, ctx.cfg.domains.first().map(|s| s.as_str()))
                };
                match verified {
                    Some(user) => {
                        let em = user.email.clone();
                        ctx.store.ensure_user(&em).ok();
                        msgs = ctx.store.list(&em, "").unwrap_or_default();
                        deleted.clear();
                        email = Some(em);
                        send(&mut io, "+OK maildrop locked and ready").await;
                    }
                    None => {
                        pending_user = None;
                        send(&mut io, "-ERR invalid credentials").await;
                    }
                }
            }
            "STLS" => {
                if implicit_tls || email.is_some() {
                    send(&mut io, "-ERR STLS not available").await;
                    continue;
                }
                let Some(acc) = ctx.acceptor.clone() else {
                    send(&mut io, "-ERR TLS not configured").await;
                    continue;
                };
                send(&mut io, "+OK Begin TLS negotiation now").await;
                let Some(tcp) = io.take_plain() else {
                    return;
                };
                match acc.accept(tcp).await {
                    Ok(t) => {
                        io = Io::new(Stream::Tls(t));
                        implicit_tls = true;
                    }
                    Err(_) => return,
                }
            }
            "QUIT" => {
                if let Some(em) = &email {
                    for i in &deleted {
                        if let Some(m) = msgs.get(i - 1) {
                            ctx.store.delete_msg(em, "", m).ok();
                        }
                    }
                    ctx.agent.mark_dirty(em);
                }
                send(&mut io, "+OK zent POP3 signing off").await;
                return;
            }
            "STAT" => {
                let Some(em) = &email else {
                    send(&mut io, "-ERR not authenticated").await;
                    continue;
                };
                let (cnt, total): (usize, u64) = msgs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !deleted.contains(&(i + 1)))
                    .fold((0, 0), |(c, t), (_, m)| (c + 1, t + m.size));
                let _ = em;
                send(&mut io, &format!("+OK {cnt} {total}")).await;
            }
            "LIST" => {
                let Some(em) = &email else {
                    send(&mut io, "-ERR not authenticated").await;
                    continue;
                };
                let alive: Vec<(usize, u64)> = msgs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !deleted.contains(&(i + 1)))
                    .map(|(i, m)| (i + 1, m.size))
                    .collect();
                if !arg.is_empty() {
                    match arg.parse::<usize>() {
                        Ok(n) => match alive.iter().find(|(i, _)| *i == n) {
                            Some((i, sz)) => send(&mut io, &format!("+OK {i} {sz}")).await,
                            None => send(&mut io, &format!("-ERR no such message {n}")).await,
                        },
                        Err(_) => send(&mut io, "-ERR bad message number").await,
                    }
                } else {
                    let total: u64 = alive.iter().map(|(_, s)| s).sum();
                    let mut out = format!("+OK {} messages ({total} octets)", alive.len());
                    for (i, sz) in &alive {
                        out.push_str(&format!("\r\n{i} {sz}"));
                    }
                    out.push_str("\r\n.");
                    send(&mut io, &out).await;
                }
                let _ = em;
            }
            "UIDL" => {
                let Some(em) = &email else {
                    send(&mut io, "-ERR not authenticated").await;
                    continue;
                };
                let alive: Vec<(usize, u64)> = msgs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !deleted.contains(&(i + 1)))
                    .map(|(i, m)| (i + 1, m.uid))
                    .collect();
                if !arg.is_empty() {
                    match arg.parse::<usize>() {
                        Ok(n) => match alive.iter().find(|(i, _)| *i == n) {
                            Some((i, uid)) => {
                                send(&mut io, &format!("+OK {i} {uid}")).await;
                            }
                            None => send(&mut io, &format!("-ERR no such message {n}")).await,
                        },
                        Err(_) => send(&mut io, "-ERR bad message number").await,
                    }
                } else {
                    let mut out = String::from("+OK");
                    for (i, uid) in &alive {
                        out.push_str(&format!("\r\n{i} {uid}"));
                    }
                    out.push_str("\r\n.");
                    send(&mut io, &out).await;
                }
                let _ = em;
            }
            "RETR" | "TOP" => {
                let Some(em) = &email else {
                    send(&mut io, "-ERR not authenticated").await;
                    continue;
                };
                let n: usize = match arg.split_whitespace().next().and_then(|x| x.parse().ok()) {
                    Some(n) => n,
                    None => {
                        send(&mut io, "-ERR bad message number").await;
                        continue;
                    }
                };
                if n == 0 || n > msgs.len() || deleted.contains(&n) {
                    send(&mut io, &format!("-ERR no such message {n}")).await;
                    continue;
                }
                let m = msgs[n - 1].clone();
                let data = match ctx.store.read(em, "", &m) {
                    Ok(d) => d,
                    Err(_) => {
                        send(&mut io, "-ERR cannot read message").await;
                        continue;
                    }
                };
                let payload = if cu == "RETR" {
                    send(&mut io, &format!("+OK {} octets", m.size)).await;
                    dot_stuff(&data)
                } else {
                    // TOP n k
                    let k = arg
                        .split_whitespace()
                        .nth(1)
                        .and_then(|x| x.parse::<usize>().ok());
                    let Some(k) = k else {
                        send(&mut io, "-ERR TOP requires two arguments").await;
                        continue;
                    };
                    send(&mut io, "+OK top of message follows").await;
                    dot_stuff(&top_of(&data, k))
                };
                let _ = io.write_all(&payload).await;
            }
            "DELE" => {
                let Some(_) = &email else {
                    send(&mut io, "-ERR not authenticated").await;
                    continue;
                };
                match arg.parse::<usize>() {
                    Ok(n) if n >= 1 && n <= msgs.len() && !deleted.contains(&n) => {
                        deleted.insert(n);
                        send(&mut io, &format!("+OK message {n} deleted")).await;
                    }
                    Ok(n) => send(&mut io, &format!("-ERR no such message {n}")).await,
                    Err(_) => send(&mut io, "-ERR bad message number").await,
                }
            }
            "RSET" => {
                if email.is_some() {
                    deleted.clear();
                    send(&mut io, "+OK").await;
                } else {
                    send(&mut io, "-ERR not authenticated").await;
                }
            }
            "NOOP" => {
                if email.is_some() {
                    send(&mut io, "+OK").await;
                } else {
                    send(&mut io, "-ERR not authenticated").await;
                }
            }
            "APOP" => send(&mut io, "-ERR APOP not supported, use USER/PASS").await,
            _ => send(&mut io, "-ERR unknown command").await,
        }
    }
}
