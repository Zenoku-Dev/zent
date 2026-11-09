// imap.rs — IMAP4rev1-сервер: LOGIN/AUTHENTICATE PLAIN, STARTTLS/implicit TLS,
// SELECT/EXAMINE, LIST/LSUB, STATUS, APPEND, SEARCH, FETCH, STORE, EXPUNGE, IDLE.
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::maildir::{self, MsgMeta};
use crate::mime::{self, Msg};
use crate::Ctx;

const LINE_MAX: usize = 16 * 1024;
const CMD_TIMEOUT: u64 = 600; // 10 минут на команду
const IDLE_TICK: u64 = 20;
const IDLE_TOTAL: u64 = 29 * 60;

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

/// Буферизованный ввод/вывод поверх Stream (свой буфер — легко апгрейдить TLS).
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

    /// Ровно n байт (тело литерала).
    async fn read_exact(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if n > 512 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "literal too big"));
        }
        while self.buf.len() - self.pos < n {
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            if self.read_more().await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in literal"));
            }
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
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

// --- чтение команды с литералами ---

/// Конец строки "{n}" или "{n+}" -> (размер, literal+)
fn literal_suffix(line: &str) -> Option<(usize, bool)> {
    let close = line.rfind('}')?;
    if close != line.len() - 1 {
        return None;
    }
    let open = line.rfind('{')?;
    if open >= close {
        return None;
    }
    let inner = &line[open + 1..close];
    let (num, plus) = match inner.strip_suffix('+') {
        Some(n) => (n, true),
        None => (inner, false),
    };
    let n: usize = num.parse().ok()?;
    Some((n, plus))
}

/// Читает команду (возможно многострочную с литералами).
/// Возвращает логическую строку (литералы заменены на плейсхолдеры "{Lk}") и сами литералы.
async fn read_command(io: &mut Io) -> io::Result<Option<(String, Vec<Vec<u8>>)>> {
    let mut line = match io.read_line(LINE_MAX).await? {
        Some(l) => l,
        None => return Ok(None),
    };
    let mut lits: Vec<Vec<u8>> = Vec::new();
    loop {
        match literal_suffix(&line) {
            Some((n, plus)) => {
                if !plus {
                    send(io, "+ Ready for literal data").await;
                }
                let data = io.read_exact(n).await?;
                lits.push(data);
                let cont = match io.read_line(LINE_MAX).await? {
                    Some(l) => l,
                    None => return Ok(Some((line, lits))),
                };
                line = format!("{}{{L{}}}\r\n{}", line, lits.len() - 1, cont);
            }
            None => return Ok(Some((line, lits))),
        }
    }
}

// --- токенизация аргументов ---

#[derive(Debug, Clone)]
enum Tok {
    S(String),
    Lit(usize),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b' ' | b'\r' | b'\n' | b'\t' => i += 1,
            b'"' => {
                let mut j = i + 1;
                let mut v: Vec<u8> = Vec::new();
                while j < b.len() && b[j] != b'"' {
                    if b[j] == b'\\' && j + 1 < b.len() {
                        j += 1;
                    }
                    v.push(b[j]);
                    j += 1;
                }
                out.push(Tok::S(String::from_utf8_lossy(&v).to_string()));
                i = if j < b.len() { j + 1 } else { j };
            }
            b'{' => {
                // плейсхолдер литерала {Lk}
                if let Some(end) = s[i..].find('}') {
                    if let Some(k) = s[i + 1..i + end]
                        .strip_prefix('L')
                        .and_then(|x| x.parse::<usize>().ok())
                    {
                        out.push(Tok::Lit(k));
                        i += end + 1;
                        continue;
                    }
                }
                let j = s[i..]
                    .find(|c: char| c == ' ' || c == '\r' || c == '\n')
                    .map(|p| i + p)
                    .unwrap_or(s.len());
                out.push(Tok::S(s[i..j].to_string()));
                i = j;
            }
            _ => {
                let j = s[i..]
                    .find(|c: char| c == ' ' || c == '\r' || c == '\n')
                    .map(|p| i + p)
                    .unwrap_or(s.len());
                out.push(Tok::S(s[i..j].to_string()));
                i = j;
            }
        }
    }
    out
}

fn tok_str(t: Option<&Tok>, lits: &[Vec<u8>]) -> String {
    match t {
        Some(Tok::S(s)) => s.clone(),
        Some(Tok::Lit(k)) => String::from_utf8_lossy(lits.get(*k).map(|v| v.as_slice()).unwrap_or(&[]))
            .to_string(),
        None => String::new(),
    }
}

// --- флаги ---

fn flags_to_imap(f: &str) -> String {
    let mut v: Vec<&str> = Vec::new();
    if f.contains('S') {
        v.push("\\Seen");
    }
    if f.contains('R') {
        v.push("\\Answered");
    }
    if f.contains('F') {
        v.push("\\Flagged");
    }
    if f.contains('T') {
        v.push("\\Deleted");
    }
    if f.contains('D') {
        v.push("\\Draft");
    }
    v.join(" ")
}

fn flags_from_imap(items: &[&str]) -> String {
    let mut s = String::new();
    for f in items {
        match f.trim_start_matches('\\').to_ascii_lowercase().as_str() {
            "seen" => s.push('S'),
            "answered" => s.push('R'),
            "flagged" => s.push('F'),
            "deleted" => s.push('T'),
            "draft" => s.push('D'),
            _ => {} // неизвестные игнорируем
        }
    }
    s
}

fn flags_of_name(name: &str) -> String {
    name.rsplit_once(":2,")
        .map(|(_, f)| f.to_string())
        .unwrap_or_default()
}

fn display_name(folder: &str) -> String {
    if folder.is_empty() {
        "INBOX".to_string()
    } else {
        format!("INBOX/{folder}")
    }
}

fn folder_exists(store: &maildir::Store, email: &str, folder: &str) -> bool {
    maildir::folder_dir(&store.user_dir(email), folder).join("cur").is_dir()
}

// --- glob для LIST (* и % — любые символы) ---

fn glob_match(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fn go(p: &[char], n: &[char]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        match p[0] {
            '*' | '%' => (0..=n.len()).any(|i| go(&p[1..], &n[i..])),
            c => !n.is_empty() && c == n[0] && go(&p[1..], &n[1..]),
        }
    }
    go(&p, &n)
}

// --- seq-set ---

fn set_contains(s: &str, val: u64, star: u64) -> bool {
    for part in s.split(',') {
        let (a, b) = match part.split_once(':') {
            Some((x, y)) => (x, y),
            None => (part, part),
        };
        let f = |t: &str| {
            if t.trim() == "*" {
                star
            } else {
                t.trim().parse::<u64>().unwrap_or(0)
            }
        };
        let (va, vb) = (f(a), f(b));
        if val >= va.min(vb) && val <= va.max(vb) {
            return true;
        }
    }
    false
}

fn match_indices(set: &str, msgs: &[MsgMeta], use_uid: bool) -> Vec<usize> {
    let star = if use_uid {
        msgs.last().map(|m| m.uid).unwrap_or(0)
    } else {
        msgs.len() as u64
    };
    let mut out = Vec::new();
    for (i, m) in msgs.iter().enumerate() {
        let v = if use_uid { m.uid } else { i as u64 + 1 };
        if set_contains(set, v, star) {
            out.push(i);
        }
    }
    out
}

// --- FETCH: разбор items ---

#[derive(Debug, Clone, PartialEq)]
enum Sec {
    Full,
    Header,
    Text,
    Fields { not: bool, fields: Vec<String> },
}

#[derive(Debug, Clone, PartialEq)]
enum Item {
    Flags,
    Uid,
    Size,
    InternalDate,
    Envelope,
    BodyStructure(bool), // extended?
    Section { peek: bool, part: Option<u32>, kind: Sec },
    Rfc822,
    Rfc822Header,
    Rfc822Text,
}

fn strip_outer_parens(s: &str) -> &str {
    let t = s.trim();
    if t.starts_with('(') && t.ends_with(')') {
        let mut depth = 0i32;
        for (i, c) in t.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return if i == t.len() - 1 { &t[1..t.len() - 1] } else { t };
                    }
                }
                _ => {}
            }
        }
    }
    t
}

fn field_list(s: &str) -> Vec<String> {
    let t = s.trim();
    let t = match (t.find('('), t.find(')')) {
        (Some(a), Some(b)) if b > a => &t[a + 1..b],
        _ => t,
    };
    t.split_whitespace()
        .map(|x| x.trim_matches('"').to_string())
        .collect()
}

fn parse_section(s: &str) -> ((Option<u32>, Sec), usize) {
    match s.find(']') {
        Some(e) => {
            let inner = &s[..e];
            let adv = e + 1;
            let it = inner.trim();
            if it.is_empty() {
                return ((None, Sec::Full), adv);
            }
            let up = it.to_ascii_uppercase();
            if up == "HEADER" {
                return ((None, Sec::Header), adv);
            }
            if up == "TEXT" {
                return ((None, Sec::Text), adv);
            }
            if up.starts_with("HEADER.FIELDS.NOT") {
                return ((None, Sec::Fields { not: true, fields: field_list(&it[17..]) }), adv);
            }
            if up.starts_with("HEADER.FIELDS") {
                return ((None, Sec::Fields { not: false, fields: field_list(&it[13..]) }), adv);
            }
            let num = it
                .split(|c: char| c == '.' || c == ' ')
                .next()
                .and_then(|x| x.parse::<u32>().ok());
            ((num, Sec::Full), adv)
        }
        None => ((None, Sec::Full), s.len()),
    }
}

fn parse_items(s: &str) -> Vec<Item> {
    let t = strip_outer_parens(s);
    let b = t.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        if b[i] == b' ' {
            i += 1;
            continue;
        }
        let up = t[i..].to_ascii_uppercase();
        if up.starts_with("BODY.PEEK[") {
            let (sec, adv) = parse_section(&t[i + 10..]);
            i += 10 + adv;
            out.push(Item::Section { peek: true, part: sec.0, kind: sec.1 });
        } else if up.starts_with("BODY[") {
            let (sec, adv) = parse_section(&t[i + 5..]);
            i += 5 + adv;
            out.push(Item::Section { peek: false, part: sec.0, kind: sec.1 });
        } else if up.starts_with("BODYSTRUCTURE") {
            i += 13;
            out.push(Item::BodyStructure(true));
        } else if up.starts_with("RFC822.SIZE") {
            i += 11;
            out.push(Item::Size);
        } else if up.starts_with("RFC822.HEADER") {
            i += 13;
            out.push(Item::Rfc822Header);
        } else if up.starts_with("RFC822.TEXT") {
            i += 11;
            out.push(Item::Rfc822Text);
        } else if up.starts_with("RFC822") {
            i += 6;
            out.push(Item::Rfc822);
        } else if up.starts_with("ENVELOPE") {
            i += 8;
            out.push(Item::Envelope);
        } else if up.starts_with("INTERNALDATE") {
            i += 12;
            out.push(Item::InternalDate);
        } else if up.starts_with("FLAGS") {
            i += 5;
            out.push(Item::Flags);
        } else if up.starts_with("UID") {
            i += 3;
            out.push(Item::Uid);
        } else if up.starts_with("ALL") {
            i += 3;
            out.extend([
                Item::Flags,
                Item::InternalDate,
                Item::Size,
                Item::Envelope,
            ]);
        } else if up.starts_with("FAST") {
            i += 4;
            out.extend([Item::Flags, Item::InternalDate, Item::Size]);
        } else if up.starts_with("FULL") {
            i += 4;
            out.extend([
                Item::Flags,
                Item::InternalDate,
                Item::Size,
                Item::Envelope,
                Item::BodyStructure(false),
            ]);
        } else if up.starts_with("BODY") {
            i += 4;
            out.push(Item::BodyStructure(false));
        } else {
            // неизвестный атом — пропустить
            let j = t[i..].find(' ').map(|p| i + p).unwrap_or(t.len());
            i = if j > i { j } else { i + 1 };
        }
    }
    out
}

fn section_name(part: Option<u32>, kind: &Sec) -> String {
    match (part, kind) {
        (Some(n), _) => n.to_string(),
        (None, Sec::Full) => String::new(),
        (None, Sec::Header) => "HEADER".to_string(),
        (None, Sec::Text) => "TEXT".to_string(),
        (None, Sec::Fields { fields, .. }) => {
            format!("HEADER.FIELDS ({})", fields.join(" "))
        }
    }
}

fn header_fields(raw: &[u8], not: bool, fields: &[String]) -> Vec<u8> {
    let m = Msg::parse(raw);
    let mut out = Vec::new();
    for (k, v) in &m.headers {
        let hit = fields.iter().any(|f| f.eq_ignore_ascii_case(k));
        if hit != not {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
    }
    out
}

fn section_data(raw: &[u8], part: Option<u32>, kind: &Sec) -> Vec<u8> {
    let (_, off) = mime::header_block(raw);
    let off = off.min(raw.len());
    match (part, kind) {
        (Some(n), Sec::Full) => {
            let msg = Msg::parse(raw);
            let parts = msg.walk_parts();
            parts
                .get((n as usize).checked_sub(1).unwrap_or(usize::MAX))
                .map(|p| p.body.to_vec())
                .unwrap_or_default()
        }
        (None, Sec::Full) => raw.to_vec(),
        (None, Sec::Header) => raw[..off].to_vec(),
        (None, Sec::Text) => raw[off..].to_vec(),
        (None, Sec::Fields { not, fields }) => header_fields(raw, *not, fields),
        (Some(_), _) => raw.to_vec(),
    }
}

fn envelope(raw: &[u8]) -> String {
    let m = Msg::parse(raw);
    let sender = m.get("Sender").or_else(|| m.get("From")).unwrap_or("");
    let reply_to = m.get("Reply-To").or_else(|| m.get("From")).unwrap_or("");
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        mime::imap_string(m.get("Date").unwrap_or("")),
        mime::imap_string(&m.subject_decoded()),
        mime::imap_addr(m.get("From").unwrap_or("")),
        mime::imap_addr(sender),
        mime::imap_addr(reply_to),
        mime::imap_addr(m.get("To").unwrap_or("")),
        mime::imap_addr(m.get("Cc").unwrap_or("")),
        mime::imap_addr(m.get("Bcc").unwrap_or("")),
        mime::imap_string(m.get("In-Reply-To").unwrap_or("")),
        mime::imap_string(m.get("Message-ID").unwrap_or("")),
    )
}

/// Сборщик ответа FETCH: "* <seq> FETCH (item item ... LIT {n}\r\n<bytes> ...)"
struct Resp {
    out: Vec<u8>,
}

impl Resp {
    fn new(seq: usize) -> Resp {
        Resp { out: format!("* {seq} FETCH (").into_bytes() }
    }
    fn sep(&mut self) {
        if self.out.last() != Some(&b'(') {
            self.out.push(b' ');
        }
    }
    fn atom(&mut self, s: &str) {
        self.sep();
        self.out.extend_from_slice(s.as_bytes());
    }
    fn lit(&mut self, name: &str, data: &[u8]) {
        self.sep();
        self.out
            .extend_from_slice(format!("{name} {{{}}}\r\n", data.len()).as_bytes());
        self.out.extend_from_slice(data);
    }
    fn finish(mut self) -> Vec<u8> {
        self.out.extend_from_slice(b")\r\n");
        self.out
    }
}

// --- SEARCH ---

#[derive(Debug, Clone)]
enum Key {
    All,
    Seen(bool),
    Answered(bool),
    Deleted(bool),
    Draft(bool),
    Flagged(bool),
    Recent(bool),
    New,
    Old,
    Header(String, String),
    Subject(String),
    Text(String),
    Body(String),
    Since(u64),
    Before(u64),
    On(u64),
    Larger(u64),
    Smaller(u64),
    UidSet(String),
    SeqSet(String),
    Not(Box<Key>),
    Or(Box<Key>, Box<Key>),
}

struct KeyParser<'a> {
    t: &'a [Tok],
    i: usize,
}

impl<'a> KeyParser<'a> {
    fn next_str(&mut self, lits: &[Vec<u8>]) -> String {
        self.i += 1;
        tok_str(self.t.get(self.i - 1), lits)
    }

    fn next(&mut self, lits: &[Vec<u8>]) -> Option<Key> {
        let s = tok_str(self.t.get(self.i), lits);
        self.i += 1;
        let up = s.to_ascii_uppercase();
        let k = match up.as_str() {
            "ALL" => Key::All,
            "ANSWERED" => Key::Answered(true),
            "UNANSWERED" => Key::Answered(false),
            "DELETED" => Key::Deleted(true),
            "UNDELETED" => Key::Deleted(false),
            "DRAFT" => Key::Draft(true),
            "UNDRAFT" => Key::Draft(false),
            "FLAGGED" => Key::Flagged(true),
            "UNFLAGGED" => Key::Flagged(false),
            "SEEN" => Key::Seen(true),
            "UNSEEN" => Key::Seen(false),
            "NEW" => Key::New,
            "OLD" => Key::Old,
            "RECENT" => Key::Recent(true),
            "FROM" => Key::Header("From".into(), self.next_str(lits)),
            "TO" => Key::Header("To".into(), self.next_str(lits)),
            "CC" => Key::Header("Cc".into(), self.next_str(lits)),
            "BCC" => Key::Header("Bcc".into(), self.next_str(lits)),
            "SUBJECT" => Key::Subject(self.next_str(lits)),
            "HEADER" => {
                let f = self.next_str(lits);
                Key::Header(f, self.next_str(lits))
            }
            "TEXT" => Key::Text(self.next_str(lits)),
            "BODY" => Key::Body(self.next_str(lits)),
            "SINCE" => Key::Since(crate::util::parse_imap_date(&self.next_str(lits)).unwrap_or(0)),
            "BEFORE" => Key::Before(crate::util::parse_imap_date(&self.next_str(lits)).unwrap_or(0)),
            "ON" => Key::On(crate::util::parse_imap_date(&self.next_str(lits)).unwrap_or(0)),
            "LARGER" => Key::Larger(self.next_str(lits).parse().unwrap_or(0)),
            "SMALLER" => Key::Smaller(self.next_str(lits).parse().unwrap_or(0)),
            "UID" => Key::UidSet(self.next_str(lits)),
            "NOT" => Key::Not(Box::new(self.next(lits)?)),
            "OR" => {
                let a = self.next(lits)?;
                let b = self.next(lits)?;
                Key::Or(Box::new(a), Box::new(b))
            }
            _ => {
                // на всякий случай — голый seq-set
                if s.contains(|c: char| c.is_ascii_digit() || c == '*') {
                    Key::SeqSet(s)
                } else {
                    Key::All
                }
            }
        };
        Some(k)
    }
}

fn keys_need_content(ks: &[Key]) -> bool {
    ks.iter().any(|k| match k {
        Key::Header(..) | Key::Subject(_) | Key::Text(_) | Key::Body(_) => true,
        Key::Not(k) => keys_need_content(std::slice::from_ref(k.as_ref())),
        Key::Or(a, b) => {
            keys_need_content(std::slice::from_ref(a.as_ref()))
                || keys_need_content(std::slice::from_ref(b.as_ref()))
        }
        _ => false,
    })
}

fn eval_key(
    k: &Key,
    m: &MsgMeta,
    seq: usize,
    raw: &[u8],
    msg: &Msg,
    total: usize,
    max_uid: u64,
) -> bool {
    match k {
        Key::All => true,
        Key::Seen(w) => m.flags.contains('S') == *w,
        Key::Answered(w) => m.flags.contains('R') == *w,
        Key::Deleted(w) => m.flags.contains('T') == *w,
        Key::Draft(w) => m.flags.contains('D') == *w,
        Key::Flagged(w) => m.flags.contains('F') == *w,
        Key::Recent(w) => !*w, // RECENT у нас всегда 0
        Key::New => false,
        Key::Old => true,
        Key::Header(f, s) => {
            let low = s.to_lowercase();
            msg.get_all(f)
                .iter()
                .any(|v| v.to_lowercase().contains(&low))
        }
        Key::Subject(s) => msg.subject_decoded().to_lowercase().contains(&s.to_lowercase()),
        Key::Text(s) => String::from_utf8_lossy(raw).to_lowercase().contains(&s.to_lowercase()),
        Key::Body(s) => String::from_utf8_lossy(msg.body).to_lowercase().contains(&s.to_lowercase()),
        Key::Since(t) => m.mtime >= *t,
        Key::Before(t) => m.mtime < *t,
        Key::On(t) => m.mtime >= *t && m.mtime < t.saturating_add(86400),
        Key::Larger(n) => m.size > *n,
        Key::Smaller(n) => m.size < *n,
        Key::UidSet(s) => set_contains(s, m.uid, max_uid),
        Key::SeqSet(s) => set_contains(s, seq as u64, total as u64),
        Key::Not(k) => !eval_key(k, m, seq, raw, msg, total, max_uid),
        Key::Or(a, b) => {
            eval_key(a, m, seq, raw, msg, total, max_uid)
                || eval_key(b, m, seq, raw, msg, total, max_uid)
        }
    }
}

// --- слушатель и сессия ---

pub async fn imap_listener(ctx: Arc<Ctx>, addr: String, implicit_tls: bool) {
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
        Err(e) => eprintln!("imap: bind {addr}: {e}"),
    }
}

async fn handle_conn(ctx: Arc<Ctx>, tcp: TcpStream, implicit_tls: bool) {
    if implicit_tls {
        let Some(acc) = ctx.acceptor.clone() else { return };
        match acc.accept(tcp).await {
            Ok(t) => run_session(ctx, Io::new(Stream::Tls(t)), true).await,
            Err(_) => {}
        }
    } else {
        run_session(ctx, Io::new(Stream::Plain(tcp)), false).await;
    }
}

fn capability(ctx: &Ctx, implicit_tls: bool, authed: bool) -> String {
    let mut c = String::from("IMAP4rev1");
    if ctx.acceptor.is_some() && !implicit_tls && !authed {
        c.push_str(" STARTTLS");
    }
    c.push_str(" AUTH=PLAIN LITERAL+ IDLE UIDPLUS");
    c
}

async fn run_session(ctx: Arc<Ctx>, mut io: Io, mut implicit_tls: bool) {
    send(
        &mut io,
        &format!("* OK [CAPABILITY {}] zent IMAP4rev1 ready", capability(&ctx, implicit_tls, false)),
    )
    .await;

    let mut email = String::new(); // пусто = не залогинен
    let mut sel: Option<(String, Vec<MsgMeta>, bool)> = None; // (folder, msgs, readonly)

    loop {
        let (line, lits) =
            match tokio::time::timeout(Duration::from_secs(CMD_TIMEOUT), read_command(&mut io)).await {
                Ok(Ok(Some(v))) => v,
                _ => return, // EOF / ошибка / таймаут
            };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        let tag = it.next().unwrap_or("*").to_string();
        let (cmd, rest) = match it.next() {
            Some(c) => (c.to_ascii_uppercase(), it.next().unwrap_or("").to_string()),
            None => {
                send(&mut io, &format!("{tag} BAD missing command")).await;
                continue;
            }
        };

        // --- любое состояние ---
        match cmd.as_str() {
            "CAPABILITY" => {
                send(
                    &mut io,
                    &format!("* CAPABILITY {}", capability(&ctx, implicit_tls, !email.is_empty())),
                )
                .await;
                send(&mut io, &format!("{tag} OK CAPABILITY completed")).await;
                continue;
            }
            "NOOP" => {
                if let Some((folder, msgs, _)) = sel.as_mut() {
                    if let Ok(list) = ctx.store.list(&email, folder) {
                        if list.len() != msgs.len() {
                            send(&mut io, &format!("* {} EXISTS", list.len())).await;
                        }
                        *msgs = list;
                    }
                }
                send(&mut io, &format!("{tag} OK NOOP completed")).await;
                continue;
            }
            "LOGOUT" => {
                send(&mut io, "* BYE zent IMAP server logging out").await;
                send(&mut io, &format!("{tag} OK LOGOUT completed")).await;
                return;
            }
            _ => {}
        }

        // --- pre-auth ---
        if email.is_empty() {
            match cmd.as_str() {
                "STARTTLS" => {
                    if implicit_tls {
                        send(&mut io, &format!("{tag} NO TLS already active")).await;
                        continue;
                    }
                    let Some(acc) = ctx.acceptor.clone() else {
                        send(&mut io, &format!("{tag} NO TLS not configured")).await;
                        continue;
                    };
                    send(&mut io, &format!("{tag} OK Begin TLS negotiation now")).await;
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
                "LOGIN" => {
                    let toks = tokenize(&rest);
                    let user = tok_str(toks.first(), &lits);
                    let pass = tok_str(toks.get(1), &lits);
                    if user.is_empty() {
                        send(&mut io, &format!("{tag} BAD LOGIN requires user and password")).await;
                        continue;
                    }
                    let verified = {
                        let db = ctx.users.read().await;
                        db.verify(&user, &pass, ctx.cfg.domains.first().map(|s| s.as_str()))
                    };
                    match verified {
                        Some(u) => {
                            email = u.email;
                            ctx.store.ensure_user(&email).ok();
                            send(
                                &mut io,
                                &format!(
                                    "* OK [CAPABILITY {}] Logged in",
                                    capability(&ctx, implicit_tls, true)
                                ),
                            )
                            .await;
                            send(&mut io, &format!("{tag} OK LOGIN completed")).await;
                        }
                        None => send(&mut io, &format!("{tag} NO [AUTHENTICATIONFAILED] LOGIN failed")).await,
                    }
                }
                "AUTHENTICATE" => {
                    let toks = tokenize(&rest);
                    let mech = tok_str(toks.first(), &lits).to_ascii_uppercase();
                    if mech != "PLAIN" {
                        send(&mut io, &format!("{tag} NO unsupported mechanism")).await;
                        continue;
                    }
                    let b64s = match toks.get(1) {
                        Some(t) => tok_str(Some(t), &lits),
                        None => {
                            send(&mut io, "+ ").await;
                            match tokio::time::timeout(
                                Duration::from_secs(CMD_TIMEOUT),
                                io.read_line(LINE_MAX),
                            )
                            .await
                            {
                                Ok(Ok(Some(l))) => l,
                                _ => return,
                            }
                        }
                    };
                    if b64s.trim() == "*" {
                        send(&mut io, &format!("{tag} BAD AUTHENTICATE cancelled")).await;
                        continue;
                    }
                    let decoded = crate::util::b64_decode(b64s.trim()).unwrap_or_default();
                    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                    let login = String::from_utf8_lossy(
                        parts.get(1).or_else(|| parts.first()).copied().unwrap_or(&[]),
                    )
                    .to_string();
                    let pass = String::from_utf8_lossy(parts.get(2).copied().unwrap_or(&[])).to_string();
                    let verified = {
                        let db = ctx.users.read().await;
                        db.verify(&login, &pass, ctx.cfg.domains.first().map(|s| s.as_str()))
                    };
                    match verified {
                        Some(u) => {
                            email = u.email;
                            ctx.store.ensure_user(&email).ok();
                            send(
                                &mut io,
                                &format!(
                                    "* OK [CAPABILITY {}] Logged in",
                                    capability(&ctx, implicit_tls, true)
                                ),
                            )
                            .await;
                            send(&mut io, &format!("{tag} OK AUTHENTICATE completed")).await;
                        }
                        None => send(&mut io, &format!("{tag} NO [AUTHENTICATIONFAILED] AUTHENTICATE failed")).await,
                    }
                }
                _ => send(&mut io, &format!("{tag} NO authenticate first")).await,
            }
            continue;
        }

        // --- authenticated ---
        match cmd.as_str() {
            "SELECT" | "EXAMINE" => {
                let name = tok_str(tokenize(&rest).first(), &lits);
                let folder = maildir::normalize_folder(&name);
                if folder.is_empty() {
                    ctx.store.ensure_user(&email).ok();
                }
                if !folder_exists(&ctx.store, &email, &folder) {
                    send(&mut io, &format!("{tag} NO [TRYCREATE] no such mailbox")).await;
                    continue;
                }
                let msgs = ctx.store.list(&email, &folder).unwrap_or_default();
                let uv = ctx.store.uidvalidity(&email, &folder);
                let un = ctx.store.uidnext(&email, &folder);
                let n = msgs.len();
                let ro = cmd == "EXAMINE";
                send(&mut io, &format!("* {n} EXISTS")).await;
                send(&mut io, "* 0 RECENT").await;
                send(
                    &mut io,
                    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
                )
                .await;
                send(&mut io, &format!("* OK [UIDVALIDITY {uv}] UIDs valid")).await;
                send(&mut io, &format!("* OK [UIDNEXT {un}] Predicted next UID")).await;
                send(
                    &mut io,
                    "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] Limited",
                )
                .await;
                let code = if ro { "READ-ONLY" } else { "READ-WRITE" };
                send(&mut io, &format!("{tag} OK [{code}] {} completed", cmd)).await;
                sel = Some((folder, msgs, ro));
            }
            "CREATE" => {
                let name = tok_str(tokenize(&rest).first(), &lits);
                let folder = maildir::normalize_folder(&name);
                if folder.is_empty() || !maildir::valid_folder(&folder) {
                    send(&mut io, &format!("{tag} NO invalid mailbox name")).await;
                    continue;
                }
                match ctx.store.create_folder(&email, &folder) {
                    Ok(true) => {
                        ctx.agent.mark_dirty(&email);
                        send(&mut io, &format!("{tag} OK CREATE completed")).await;
                    }
                    _ => send(&mut io, &format!("{tag} NO mailbox already exists")).await,
                }
            }
            "DELETE" => {
                let name = tok_str(tokenize(&rest).first(), &lits);
                let folder = maildir::normalize_folder(&name);
                if folder.is_empty() {
                    send(&mut io, &format!("{tag} NO cannot delete INBOX")).await;
                    continue;
                }
                match ctx.store.delete_folder(&email, &folder) {
                    Ok(true) => {
                        ctx.agent.mark_dirty(&email);
                        if let Some((f, _, _)) = sel.as_ref() {
                            if f == &folder {
                                sel = None;
                            }
                        }
                        send(&mut io, &format!("{tag} OK DELETE completed")).await;
                    }
                    _ => send(&mut io, &format!("{tag} NO no such mailbox")).await,
                }
            }
            "RENAME" => {
                let toks = tokenize(&rest);
                let from = maildir::normalize_folder(&tok_str(toks.first(), &lits));
                let to = maildir::normalize_folder(&tok_str(toks.get(1), &lits));
                if from.is_empty() || to.is_empty() || !maildir::valid_folder(&to) {
                    send(&mut io, &format!("{tag} NO invalid rename")).await;
                    continue;
                }
                match ctx.store.rename_folder(&email, &from, &to) {
                    Ok(true) => {
                        ctx.agent.mark_dirty(&email);
                        if let Some((f, _, _)) = sel.as_ref() {
                            if f == &from {
                                sel = None;
                            }
                        }
                        send(&mut io, &format!("{tag} OK RENAME completed")).await;
                    }
                    _ => send(&mut io, &format!("{tag} NO rename failed")).await,
                }
            }
            "LIST" | "LSUB" => {
                let toks = tokenize(&rest);
                let mut pat = tok_str(toks.get(1).or(toks.first()), &lits)
                    .trim_matches('"')
                    .to_string();
                if pat.is_empty() {
                    pat = "*".into();
                }
                let pat_up = pat.to_ascii_uppercase();
                for f in ctx.store.list_folders(&email) {
                    let d = display_name(&f);
                    if glob_match(&pat_up, &d.to_ascii_uppercase()) {
                        send(
                            &mut io,
                            &format!(
                                "* {} (\\HasNoChildren) \"/\" \"{}\"",
                                cmd, d
                            ),
                        )
                        .await;
                    }
                }
                send(&mut io, &format!("{tag} OK {} completed", cmd)).await;
            }
            "STATUS" => {
                let toks = tokenize(&rest);
                let name = tok_str(toks.first(), &lits);
                let folder = maildir::normalize_folder(&name);
                if !folder_exists(&ctx.store, &email, &folder) {
                    send(&mut io, &format!("{tag} NO no such mailbox")).await;
                    continue;
                }
                let items_raw = rest
                    .find('(')
                    .and_then(|a| rest[a..].find(')').map(|b| &rest[a + 1..a + b]))
                    .unwrap_or("MESSAGES UNSEEN UIDNEXT UIDVALIDITY RECENT");
                let want: Vec<String> = items_raw
                    .to_ascii_uppercase()
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                let list = ctx.store.list(&email, &folder).unwrap_or_default();
                let uv = ctx.store.uidvalidity(&email, &folder);
                let un = ctx.store.uidnext(&email, &folder);
                let unseen = list.iter().filter(|m| !m.flags.contains('S')).count();
                let mut parts: Vec<String> = Vec::new();
                if want.is_empty() || want.iter().any(|w| w == "MESSAGES") {
                    parts.push(format!("MESSAGES {}", list.len()));
                }
                if want.is_empty() || want.iter().any(|w| w == "UNSEEN") {
                    parts.push(format!("UNSEEN {unseen}"));
                }
                if want.is_empty() || want.iter().any(|w| w == "UIDNEXT") {
                    parts.push(format!("UIDNEXT {un}"));
                }
                if want.is_empty() || want.iter().any(|w| w == "UIDVALIDITY") {
                    parts.push(format!("UIDVALIDITY {uv}"));
                }
                if want.is_empty() || want.iter().any(|w| w == "RECENT") {
                    parts.push("RECENT 0".into());
                }
                send(
                    &mut io,
                    &format!("* STATUS {} ({})", display_name(&folder), parts.join(" ")),
                )
                .await;
                send(&mut io, &format!("{tag} OK STATUS completed")).await;
            }
            "APPEND" => {
                if let Some((_, _, ro)) = sel.as_ref() {
                    if *ro {
                        send(&mut io, &format!("{tag} NO mailbox is read-only")).await;
                        continue;
                    }
                }
                let toks = tokenize(&rest);
                let name = tok_str(toks.first(), &lits);
                let folder = maildir::normalize_folder(&name);
                if folder.is_empty() {
                    ctx.store.ensure_user(&email).ok();
                } else if !maildir::valid_folder(&folder) || !folder_exists(&ctx.store, &email, &folder) {
                    send(&mut io, &format!("{tag} NO [TRYCREATE] no such mailbox")).await;
                    continue;
                }
                // литерал = письмо
                let Some(k) = toks.iter().find_map(|t| match t {
                    Tok::Lit(k) => Some(*k),
                    _ => None,
                }) else {
                    send(&mut io, &format!("{tag} BAD APPEND requires a literal")).await;
                    continue;
                };
                let data = lits.get(k).cloned().unwrap_or_default();
                // флаги в скобках (опционально)
                let mut flag_items: Vec<String> = Vec::new();
                let mut in_flags = false;
                for t in toks.iter().skip(1) {
                    match t {
                        Tok::Lit(_) => break,
                        Tok::S(s) => {
                            let mut s = s.trim_matches('"').to_string();
                            if s.starts_with('(') {
                                in_flags = true;
                                s.remove(0);
                            }
                            let mut closed = false;
                            if s.ends_with(')') {
                                s.pop();
                                closed = true;
                            }
                            if in_flags && !s.is_empty() {
                                flag_items.push(s);
                            }
                            if closed {
                                in_flags = false;
                            }
                        }
                    }
                }
                match ctx.store.deliver(&email, &data, &folder) {
                    Ok(uid) => {
                        if !flag_items.is_empty() {
                            let refs: Vec<&str> =
                                flag_items.iter().map(|s| s.as_str()).collect();
                            let chars = flags_from_imap(&refs);
                            if let Ok(list) = ctx.store.list(&email, &folder) {
                                if let Some(m) = list.iter().find(|m| m.uid == uid) {
                                    let _ = ctx.store.set_flags(&email, &folder, m, &chars);
                                }
                            }
                        }
                        let uv = ctx.store.uidvalidity(&email, &folder);
                        ctx.agent.mark_dirty(&email);
                        send(
                            &mut io,
                            &format!("{tag} OK [APPENDUID {uv} {uid}] APPEND completed"),
                        )
                        .await;
                    }
                    Err(_) => send(&mut io, &format!("{tag} NO APPEND failed")).await,
                }
            }
            "CHECK" | "CLOSE" | "EXPUNGE" | "SEARCH" | "FETCH" | "STORE" | "IDLE" => {
                let Some((folder, msgs, readonly)) = sel.as_mut() else {
                    send(&mut io, &format!("{tag} NO no mailbox selected")).await;
                    continue;
                };
                match cmd.as_str() {
                    "CHECK" => {
                        if let Ok(list) = ctx.store.list(&email, folder) {
                            if list.len() != msgs.len() {
                                send(&mut io, &format!("* {} EXISTS", list.len())).await;
                            }
                            *msgs = list;
                        }
                        send(&mut io, &format!("{tag} OK CHECK completed")).await;
                    }
                    "CLOSE" => {
                        if !*readonly {
                            for m in msgs.iter().filter(|m| m.flags.contains('T')) {
                                ctx.store.delete_msg(&email, folder, m).ok();
                            }
                            ctx.agent.mark_dirty(&email);
                        }
                        sel = None;
                        send(&mut io, &format!("{tag} OK CLOSE completed")).await;
                    }
                    "EXPUNGE" => {
                        if *readonly {
                            send(&mut io, &format!("{tag} NO mailbox is read-only")).await;
                            continue;
                        }
                        if let Ok(list) = ctx.store.list(&email, folder) {
                            *msgs = list;
                        }
                        let idxs: Vec<usize> = msgs
                            .iter()
                            .enumerate()
                            .filter(|(_, m)| m.flags.contains('T'))
                            .map(|(i, _)| i)
                            .collect();
                        for &i in idxs.iter().rev() {
                            let m = msgs[i].clone();
                            ctx.store.delete_msg(&email, folder, &m).ok();
                            msgs.remove(i);
                            send(&mut io, &format!("* {} EXPUNGE", i + 1)).await;
                        }
                        ctx.agent.mark_dirty(&email);
                        send(&mut io, &format!("{tag} OK EXPUNGE completed")).await;
                    }
                    "SEARCH" => {
                        let uid_mode = {
                            let t = rest.trim_start().to_ascii_uppercase();
                            t.starts_with("UID ")
                        };
                        let arg_rest = if uid_mode {
                            rest.trim_start()[4..].trim_start().to_string()
                        } else {
                            rest.clone()
                        };
                        let toks = tokenize(&arg_rest);
                        let mut p = KeyParser { t: &toks, i: 0 };
                        let mut keys: Vec<Key> = Vec::new();
                        while let Some(k) = p.next(&lits) {
                            keys.push(k);
                        }
                        if keys.is_empty() {
                            keys.push(Key::All);
                        }
                        let need = keys_need_content(&keys);
                        let max_uid = msgs.last().map(|m| m.uid).unwrap_or(0);
                        let mut out = String::from("* SEARCH");
                        for (i, m) in msgs.iter().enumerate() {
                            let raw: Vec<u8> = if need {
                                ctx.store.read(&email, folder, m).unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            let msg = Msg::parse(&raw);
                            let seq = i + 1;
                            if keys.iter().all(|k| {
                                eval_key(k, m, seq, &raw, &msg, msgs.len(), max_uid)
                            }) {
                                out.push_str(&format!(
                                    " {}",
                                    if uid_mode { m.uid } else { seq as u64 }
                                ));
                            }
                        }
                        send(&mut io, &out).await;
                        send(&mut io, &format!("{tag} OK {}SEARCH completed", if uid_mode { "UID " } else { "" })).await;
                    }
                    "FETCH" => {
                        let uid_mode = {
                            let t = rest.trim_start().to_ascii_uppercase();
                            t.starts_with("UID ")
                        };
                        let arg_rest = if uid_mode {
                            rest.trim_start()[4..].trim_start().to_string()
                        } else {
                            rest.clone()
                        };
                        let arg_rest = arg_rest.trim_start();
                        let Some(sp) = arg_rest.find(' ') else {
                            send(&mut io, &format!("{tag} BAD FETCH requires seq-set and items")).await;
                            continue;
                        };
                        let set = arg_rest[..sp].trim();
                        let items = parse_items(arg_rest[sp..].trim());
                        if items.is_empty() {
                            send(&mut io, &format!("{tag} BAD no fetch items")).await;
                            continue;
                        }
                        let mut items = items;
                        if uid_mode && !items.iter().any(|i| *i == Item::Uid) {
                            items.insert(0, Item::Uid);
                        }
                        let matched = match_indices(set, msgs, uid_mode);
                        let need_raw = items.iter().any(|i| {
                            matches!(
                                i,
                                Item::Envelope
                                    | Item::BodyStructure(_)
                                    | Item::Section { .. }
                                    | Item::Rfc822
                                    | Item::Rfc822Header
                                    | Item::Rfc822Text
                            )
                        });
                        for &i in matched.iter() {
                            let raw: Vec<u8> = if need_raw {
                                ctx.store.read(&email, folder, &msgs[i]).unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            let m = &msgs[i];
                            let mut resp = Resp::new(i + 1);
                            let mut need_seen = false;
                            for item in &items {
                                match item {
                                    Item::Flags => resp.atom(&format!("FLAGS ({})", flags_to_imap(&m.flags))),
                                    Item::Uid => resp.atom(&format!("UID {}", m.uid)),
                                    Item::Size => resp.atom(&format!("RFC822.SIZE {}", m.size)),
                                    Item::InternalDate => resp.atom(&format!(
                                        "INTERNALDATE \"{}\"",
                                        crate::util::imap_date(m.mtime)
                                    )),
                                    Item::Envelope => resp.atom(&format!("ENVELOPE {}", envelope(&raw))),
                                    Item::BodyStructure(ext) => resp.atom(&format!(
                                        "{} {}",
                                        if *ext { "BODYSTRUCTURE" } else { "BODY" },
                                        mime::bodystructure(&raw, *ext)
                                    )),
                                    Item::Section { peek, part, kind } => {
                                        let data = section_data(&raw, *part, kind);
                                        let nm = section_name(*part, kind);
                                        resp.lit(&format!("BODY[{nm}]"), &data);
                                        if !*peek {
                                            need_seen = true;
                                        }
                                    }
                                    Item::Rfc822 => {
                                        resp.lit("RFC822", &raw);
                                        need_seen = true;
                                    }
                                    Item::Rfc822Header => {
                                        let (_, off) = mime::header_block(&raw);
                                        let off = off.min(raw.len());
                                        resp.lit("RFC822.HEADER", &raw[..off]);
                                    }
                                    Item::Rfc822Text => {
                                        let (_, off) = mime::header_block(&raw);
                                        let off = off.min(raw.len());
                                        resp.lit("RFC822.TEXT", &raw[off..]);
                                        need_seen = true;
                                    }
                                }
                            }
                            let _ = io.write_all(&resp.finish()).await;
                            // не-peek BODY[] ставит \Seen
                            if need_seen && !*readonly && !m.flags.contains('S') {
                                let nf = format!("{}S", m.flags);
                                if let Ok(nm) = ctx.store.set_flags(&email, folder, m, &nf) {
                                    msgs[i].name = nm;
                                    msgs[i].flags = flags_of_name(&msgs[i].name);
                                }
                            }
                        }
                        send(
                            &mut io,
                            &format!(
                                "{tag} OK {}FETCH completed",
                                if uid_mode { "UID " } else { "" }
                            ),
                        )
                        .await;
                    }
                    "STORE" => {
                        if *readonly {
                            send(&mut io, &format!("{tag} NO mailbox is read-only")).await;
                            continue;
                        }
                        let uid_mode = {
                            let t = rest.trim_start().to_ascii_uppercase();
                            t.starts_with("UID ")
                        };
                        let arg_rest = if uid_mode {
                            rest.trim_start()[4..].trim_start().to_string()
                        } else {
                            rest.clone()
                        };
                        let arg_rest = arg_rest.trim_start();
                        let Some(sp1) = arg_rest.find(' ') else {
                            send(&mut io, &format!("{tag} BAD STORE requires arguments")).await;
                            continue;
                        };
                        let set = arg_rest[..sp1].trim().to_string();
                        let rest2 = arg_rest[sp1..].trim_start();
                        let (mode_raw, fl_raw) = match rest2.find(' ') {
                            Some(sp2) => (rest2[..sp2].to_string(), rest2[sp2..].trim().to_string()),
                            None => (rest2.to_string(), String::new()),
                        };
                        let mode_up = mode_raw.to_ascii_uppercase();
                        let silent = mode_up.ends_with(".SILENT");
                        let base = if silent {
                            mode_up[..mode_up.len() - 7].to_string()
                        } else {
                            mode_up
                        };
                        if !matches!(base.as_str(), "FLAGS" | "+FLAGS" | "-FLAGS") {
                            send(&mut io, &format!("{tag} BAD STORE mode must be FLAGS/+FLAGS/-FLAGS")).await;
                            continue;
                        }
                        let fl = fl_raw.trim_matches(|c| c == '(' || c == ')');
                        let refs: Vec<&str> = fl.split_whitespace().collect();
                        let add = flags_from_imap(&refs);
                        let matched = match_indices(&set, msgs, uid_mode);
                        for i in matched {
                            let cur = msgs[i].flags.clone();
                            let new: String = match base.as_str() {
                                "+FLAGS" => format!("{cur}{add}"),
                                "-FLAGS" => cur.chars().filter(|c| !add.contains(*c)).collect(),
                                _ => add.clone(),
                            };
                            if let Ok(nm) = ctx.store.set_flags(&email, folder, &msgs[i], &new) {
                                msgs[i].name = nm;
                                msgs[i].flags = flags_of_name(&msgs[i].name);
                            }
                            if !silent {
                                send(
                                    &mut io,
                                    &format!(
                                        "* {} FETCH (FLAGS ({}))",
                                        i + 1,
                                        flags_to_imap(&msgs[i].flags)
                                    ),
                                )
                                .await;
                            }
                        }
                        send(
                            &mut io,
                            &format!(
                                "{tag} OK {}STORE completed",
                                if uid_mode { "UID " } else { "" }
                            ),
                        )
                        .await;
                    }
                    "IDLE" => {
                        send(&mut io, "+ idling").await;
                        let start = Instant::now();
                        loop {
                            tokio::select! {
                                r = io.read_line(LINE_MAX) => {
                                    match r {
                                        Ok(Some(l)) => {
                                            if l.trim().eq_ignore_ascii_case("DONE") {
                                                send(&mut io, &format!("{tag} OK IDLE terminated")).await;
                                                break;
                                            }
                                            // прочее во время IDLE игнорируем
                                        }
                                        _ => return,
                                    }
                                }
                                _ = tokio::time::sleep(Duration::from_secs(IDLE_TICK)) => {
                                    if start.elapsed().as_secs() > IDLE_TOTAL {
                                        send(&mut io, &format!("{tag} OK IDLE timeout")).await;
                                        break;
                                    }
                                    if let Some((f, ms, _)) = sel.as_mut() {
                                        if let Ok(list) = ctx.store.list(&email, f) {
                                            if list.len() != ms.len() {
                                                send(&mut io, &format!("* {} EXISTS", list.len())).await;
                                            }
                                            *ms = list;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => send(&mut io, &format!("{tag} BAD unknown command")).await,
        }
    }
}
