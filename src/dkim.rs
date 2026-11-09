// dkim.rs — DKIM ed25519-sha256 (RFC 8463) через ring: ключи, подписание, верификация.
//  - генерация: Ed25519KeyPair::generate_pkcs8, pkcs8 в db/dkim/<domain>.pkcs8
//  - подписание: relaxed/relaxed, h= from:to:subject:date:message-id:cc
//  - верификация: relaxed и simple, ed25519 (raw 32 байта) и rsa-sha256 (SPKI DER)
use std::path::{Path, PathBuf};

use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::util::{b64_decode, b64_encode, now, sha256};

#[derive(Debug, Clone)]
pub struct DkimResult {
    pub passed: bool,
    pub domain: String,
}

// --- ключи ---

fn key_path(db: &Path, domain: &str) -> PathBuf {
    db.join("dkim").join(format!("{}.pkcs8", domain.to_lowercase()))
}

fn load_pair(db: &Path, domain: &str) -> Option<Ed25519KeyPair> {
    let data = std::fs::read(key_path(db, domain)).ok()?;
    Ed25519KeyPair::from_pkcs8(&data).ok()
}

/// Есть ключ — вернуть pubkey (b64), нет — сгенерировать и сохранить.
pub fn ensure_keypair(db: &Path, domain: &str) -> std::io::Result<String> {
    let path = key_path(db, domain);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if let Some(kp) = load_pair(db, domain) {
        return Ok(b64_encode(kp.public_key().as_ref()));
    }
    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("ring: {e}")))?;
    let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("ring: {e}")))?;
    std::fs::write(&path, doc.as_ref())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(b64_encode(kp.public_key().as_ref()))
}

// --- разбор письма ---

/// (сырые поля заголовков без завершающего CRLF, тело)
fn split_message(raw: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (hb, body): (&[u8], &[u8]) = match sep {
        Some(i) => (&raw[..i + 2], &raw[i + 4..]),
        None => (raw, &[]),
    };
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    loop {
        let rel = hb[pos..].windows(2).position(|w| w == b"\r\n");
        let end = match rel {
            Some(p) => pos + p,
            None => hb.len(),
        };
        let line = &hb[pos..end];
        if !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') && !cur.is_empty() {
            // folded continuation
            cur.extend_from_slice(b"\r\n");
            cur.extend_from_slice(line);
        } else {
            if !cur.is_empty() {
                fields.push(std::mem::take(&mut cur));
            }
            cur = line.to_vec();
        }
        if rel.is_none() {
            break;
        }
        pos = end + 2;
    }
    if !cur.is_empty() {
        fields.push(cur);
    }
    (fields, body.to_vec())
}

fn hname(f: &[u8]) -> &[u8] {
    match f.iter().position(|&b| b == b':') {
        Some(i) => &f[..i],
        None => f,
    }
}

fn split_field(f: &[u8]) -> (&[u8], &[u8]) {
    match f.iter().position(|&b| b == b':') {
        Some(i) => (&f[..i], &f[i + 1..]),
        None => (f, &[]),
    }
}

/// relaxed-канонизация значения заголовка: unfold, схлопнуть WSP, trim.
fn canon_value(v: &[u8]) -> String {
    let mut out = String::with_capacity(v.len());
    let mut wsp = false;
    for &b in v {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            wsp = true;
        } else {
            if wsp && !out.is_empty() {
                out.push(' ');
            }
            wsp = false;
            out.push(b as char); // значения заголовков почти всегда ASCII
        }
    }
    out
}

/// relaxed body: схлопнуть WSP, trim trailing WSP строк, убрать пустые строки в конце.
fn canon_body_relaxed(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + 2);
    let mut line: Vec<u8> = Vec::new();
    for &b in body {
        if b == b'\n' {
            push_relaxed_line(&mut out, &line);
            line.clear();
        } else {
            line.push(b);
        }
    }
    if !line.is_empty() {
        push_relaxed_line(&mut out, &line);
    }
    while out.ends_with(b"\r\n\r\n") {
        out.truncate(out.len() - 2);
    }
    if out.is_empty() {
        out = b"\r\n".to_vec();
    }
    out
}

fn push_relaxed_line(out: &mut Vec<u8>, line: &[u8]) {
    let mut coll: Vec<u8> = Vec::with_capacity(line.len());
    let mut wsp = false;
    for &b in line {
        if matches!(b, b' ' | b'\t' | b'\r') {
            wsp = true;
        } else {
            if wsp && !coll.is_empty() {
                coll.push(b' ');
            }
            wsp = false;
            coll.push(b);
        }
    }
    while coll.last() == Some(&b' ') {
        coll.pop();
    }
    out.extend_from_slice(&coll);
    out.extend_from_slice(b"\r\n");
}

/// simple body: убрать пустые строки в конце, гарантировать CRLF; пустое тело = CRLF.
fn canon_body_simple(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + 2);
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\r' && i + 1 < body.len() && body[i + 1] == b'\n' {
            out.extend_from_slice(b"\r\n");
            i += 2;
        } else if body[i] == b'\n' {
            out.extend_from_slice(b"\r\n");
            i += 1;
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    while out.ends_with(b"\r\n\r\n") {
        out.truncate(out.len() - 2);
    }
    if out.is_empty() {
        return b"\r\n".to_vec();
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

// --- подписание ---

/// Подписать письмо своим ключом. Возвращает готовую строку заголовка
/// "DKIM-Signature: ..." (без CRLF в конце) или None (нет ключа/заголовков).
pub fn sign(db: &Path, domain: &str, selector: &str, raw: &[u8]) -> Option<String> {
    let kp = load_pair(db, domain)?;
    let (fields, body) = split_message(raw);
    const H: [&str; 6] = ["from", "to", "subject", "date", "message-id", "cc"];
    let mut picked: Vec<&[u8]> = Vec::new();
    let mut h_list = String::new();
    for name in H {
        if let Some((_, f)) = fields
            .iter()
            .enumerate()
            .rev()
            .find(|(_, f)| hname(f).eq_ignore_ascii_case(name.as_bytes()))
        {
            picked.push(f);
            if !h_list.is_empty() {
                h_list.push(':');
            }
            h_list.push_str(name);
        }
    }
    if h_list.is_empty() {
        return None;
    }
    // канонизованные подписываемые заголовки (снизу вверх по копиям)
    let mut input: Vec<u8> = Vec::new();
    for f in &picked {
        let (n, v) = split_field(f);
        for &b in n {
            input.push(b.to_ascii_lowercase());
        }
        input.push(b':');
        input.extend_from_slice(canon_value(v).as_bytes());
        input.extend_from_slice(b"\r\n");
    }
    let cbody = canon_body_relaxed(&body);
    let bh = b64_encode(&sha256(&cbody));
    let value = format!(
        "v=1; a=ed25519-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
        domain.to_lowercase(),
        selector,
        now(),
        h_list,
        bh
    );
    input.extend_from_slice(b"dkim-signature:");
    input.extend_from_slice(value.as_bytes());
    let sig = kp.sign(&sha256(&input));
    Some(format!("DKIM-Signature: {}{}", value, b64_encode(sig.as_ref())))
}

// --- верификация ---

pub async fn verify_all(raw: &[u8]) -> Vec<DkimResult> {
    let (fields, body) = split_message(raw);
    let mut out = Vec::new();
    for f in &fields {
        if hname(f).eq_ignore_ascii_case(b"dkim-signature") {
            out.push(verify_one(f, &fields, &body).await);
        }
    }
    out
}

fn get_tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn parse_tags(value: &str) -> Vec<(String, String)> {
    let mut tags = Vec::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            tags.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    tags
}

/// Убрать значение b= тега из сырого DKIM-Signature (folding сохраняется).
fn strip_b_value(field: &[u8]) -> Vec<u8> {
    let colon = match field.iter().position(|&b| b == b':') {
        Some(i) => i,
        None => return field.to_vec(),
    };
    let head = &field[..=colon];
    let v = &field[colon + 1..];
    let n = v.len();
    let bytes = v;
    let mut b_range: Option<(usize, usize)> = None;
    let mut i = 0usize;
    while i < n {
        while i < n && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        let name_start = i;
        while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let name = &bytes[name_start..i];
        while i < n && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            while i < n && bytes[i] != b';' {
                i += 1;
            }
            i += 1;
            continue;
        }
        i += 1;
        while i < n && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        let val_start = i;
        while i < n && bytes[i] != b';' {
            i += 1;
        }
        let mut val_end = i;
        while val_end > val_start && matches!(bytes[val_end - 1], b' ' | b'\t' | b'\r' | b'\n') {
            val_end -= 1;
        }
        if name == b"b" && b_range.is_none() {
            b_range = Some((val_start, val_end));
        }
        i += 1;
    }
    let mut out = head.to_vec();
    match b_range {
        Some((a, b)) => {
            out.extend_from_slice(&v[..a]);
            out.extend_from_slice(&v[b..]);
        }
        None => out.extend_from_slice(v),
    }
    out
}

fn push_canon_header(out: &mut Vec<u8>, f: &[u8], relaxed: bool) {
    if relaxed {
        let (n, v) = split_field(f);
        for &b in n {
            out.push(b.to_ascii_lowercase());
        }
        out.push(b':');
        out.extend_from_slice(canon_value(v).as_bytes());
    } else {
        out.extend_from_slice(f);
    }
    out.extend_from_slice(b"\r\n");
}

fn push_canon_dkim(out: &mut Vec<u8>, f: &[u8], relaxed: bool) {
    let stripped = strip_b_value(f);
    if relaxed {
        let (_, v) = split_field(&stripped);
        out.extend_from_slice(b"dkim-signature:");
        out.extend_from_slice(canon_value(v).as_bytes());
        out.extend_from_slice(b"\r\n");
    } else {
        out.extend_from_slice(&stripped);
        out.extend_from_slice(b"\r\n");
    }
}

async fn verify_one(field: &[u8], fields: &[Vec<u8>], body: &[u8]) -> DkimResult {
    let mut res = DkimResult {
        passed: false,
        domain: String::new(),
    };
    let value = String::from_utf8_lossy(split_field(field).1).replace("\r\n", "");
    let tags = parse_tags(&value);
    let (d, s, h, btag, bh, av) = match (
        get_tag(&tags, "d"),
        get_tag(&tags, "s"),
        get_tag(&tags, "h"),
        get_tag(&tags, "b"),
        get_tag(&tags, "bh"),
        get_tag(&tags, "a"),
    ) {
        (Some(a), Some(b), Some(c), Some(e), Some(f), Some(g)) => {
            (a.to_string(), b.to_string(), c.to_string(), e.to_string(), f.to_string(), g.to_string())
        }
        _ => return res,
    };
    let d = d.trim().trim_end_matches('.').to_lowercase();
    res.domain = d.clone();
    let c = get_tag(&tags, "c").unwrap_or("simple/simple").to_lowercase();
    let (c_head, c_body) = match c.split_once('/') {
        Some((a, b)) => (a.trim().to_string(), b.trim().to_string()),
        None => (c.trim().to_string(), "simple".to_string()),
    };
    let relaxed = c_head == "relaxed";
    // 1) body hash
    let cb = if c_body == "simple" {
        canon_body_simple(body)
    } else {
        canon_body_relaxed(body)
    };
    let want_bh = match b64_decode(&bh) {
        Some(v) => v,
        None => return res,
    };
    if sha256(&cb).to_vec() != want_bh {
        return res;
    }
    // 2) хеш-вход: канонизованные заголовки из h= (снизу вверх по копиям) + dkim без b=
    let names: Vec<String> = h
        .split(':')
        .map(|x| x.trim().to_ascii_lowercase())
        .filter(|x| !x.is_empty())
        .collect();
    if !names.iter().any(|n| n == "from") {
        return res; // from обязателен в h=
    }
    let mut input: Vec<u8> = Vec::new();
    let mut used = vec![false; fields.len()];
    for name in &names {
        if let Some((idx, f)) = fields
            .iter()
            .enumerate()
            .rev()
            .find(|(i, f)| !used[*i] && hname(f).eq_ignore_ascii_case(name.as_bytes()))
        {
            used[idx] = true;
            push_canon_header(&mut input, f, relaxed);
        }
    }
    push_canon_dkim(&mut input, field, relaxed);
    // 3) публичный ключ из DNS
    let qname = format!("{}._domainkey.{}", s.trim(), d);
    let recs = tokio::task::spawn_blocking(move || crate::dns::txt_lookup(&qname))
        .await
        .unwrap_or_default();
    let keyrec = match recs.iter().find(|r| r.contains("p=")) {
        Some(k) => k.clone(),
        None => return res,
    };
    let mut pk: Option<Vec<u8>> = None;
    for part in keyrec.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            match k.trim() {
                "p" => pk = b64_decode(v.trim()),
                _ => {}
            }
        }
    }
    let pk = match pk {
        Some(p) if !p.is_empty() => p,
        _ => return res, // revoked / битый ключ
    };
    let sig = match b64_decode(&btag) {
        Some(x) => x,
        None => return res,
    };
    let av = av.trim().to_lowercase();
    let ok = if av == "ed25519-sha256" {
        if pk.len() != 32 {
            false
        } else {
            let h = sha256(&input);
            UnparsedPublicKey::new(&signature::ED25519, &pk).verify(&h, &sig).is_ok()
        }
    } else if av == "rsa-sha256" {
        // p= — SPKI DER; ring сам считает SHA-256 от входа
        UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &pk)
            .verify(&input, &sig)
            .is_ok()
    } else {
        false
    };
    res.passed = ok;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify_offline() {
        let tmp = std::env::temp_dir().join(format!("zent-dkim-{}", crate::util::hex(&crate::util::urandom(4))));
        let dom = "example.com";
        let _ = ensure_keypair(&tmp, dom).unwrap();
        let raw = b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: hi there\r\nDate: Tue, 03 Nov 2026 10:00:00 +0000\r\n\r\nHello  world  \r\n\r\n\r\n";
        let hdr = sign(&tmp, dom, "zent", raw).unwrap();
        assert!(hdr.contains("a=ed25519-sha256"));
        // верификация — DNS недоступен, но bh и хеш-вход считаются; проверим канонизацию
        let (fields, body) = split_message(raw);
        assert_eq!(fields.len(), 4);
        assert_eq!(canon_body_relaxed(&body), b"Hello world\r\n");
        assert_eq!(canon_body_simple(b"hi\r\n\r\n\r\n"), b"hi\r\n");
        assert_eq!(canon_body_simple(b""), b"\r\n");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn strip_b() {
        let f = b"DKIM-Signature: v=1; a=ed25519-sha256; b=AAAABBBB; h=from";
        let s = String::from_utf8(strip_b_value(f)).unwrap();
        assert!(s.contains("b=; h=from"));
        assert!(!s.contains("AAAABBBB"));
    }
}
