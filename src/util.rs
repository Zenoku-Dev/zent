// util.rs — мелочи: время, b64, hex, случайности. Всё своё, без зависимостей.
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn urandom(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .expect("/dev/urandom");
    b
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// --- base64 (свой) ---
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(d: &[u8]) -> String {
    let mut out = String::with_capacity((d.len() + 2) / 3 * 4);
    for ch in d.chunks(3) {
        let b0 = ch[0] as u32;
        let b1 = *ch.get(1).unwrap_or(&0) as u32;
        let b2 = *ch.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// --- SHA-256 (свой) ---
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_multi(&[data])
}

// haсh нескольких кусков подряд (для потоковой hash'ировки)
pub fn sha256_multi(parts: &[&[u8]]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let total: u64 = parts.iter().map(|p| p.len() as u64).sum();
    let mut process = |block: &[u8]| {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    };
    let mut buf = [0u8; 64];
    let mut fill = 0usize;
    for part in parts {
        let mut off = 0usize;
        while off < part.len() {
            let take = std::cmp::min(64 - fill, part.len() - off);
            buf[fill..fill + take].copy_from_slice(&part[off..off + take]);
            fill += take;
            off += take;
            if fill == 64 {
                process(&buf);
                fill = 0;
                buf = [0u8; 64];
            }
        }
    }
    let bitlen = total * 8;
    buf[fill] = 0x80;
    fill += 1;
    if fill > 56 {
        process(&buf[..]);
        buf = [0u8; 64];
    }
    buf[56..64].copy_from_slice(&bitlen.to_be_bytes());
    process(&buf);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// соль + итеративный sha256: формат zent1$<salt>$<hash>
pub const HASH_ROUNDS: u32 = 12000;

pub fn hash_password(pass: &str) -> String {
    let salt = urandom(16);
    let mut acc = salt.clone();
    acc.extend_from_slice(pass.as_bytes());
    let mut h = sha256(&acc);
    for _ in 1..HASH_ROUNDS {
        let mut inp = salt.clone();
        inp.extend_from_slice(&h);
        h = sha256(&inp);
    }
    format!("zent1${}${}", hex(&salt), hex(&h))
}

pub fn verify_password(pass: &str, stored: &str) -> bool {
    let p: Vec<&str> = stored.trim().split('$').collect();
    if p.len() != 3 || p[0] != "zent1" {
        return false;
    }
    let salt = match unhex(p[1]) {
        Some(s) => s,
        None => return false,
    };
    let want = match unhex(p[2]) {
        Some(s) => s,
        None => return false,
    };
    let mut acc = salt.clone();
    acc.extend_from_slice(pass.as_bytes());
    let mut h = sha256(&acc);
    for _ in 1..HASH_ROUNDS {
        let mut inp = salt.clone();
        inp.extend_from_slice(&h);
        h = sha256(&inp);
    }
    h.to_vec() == want
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

// --- даты ---
// days since epoch -> (y, m, d). Алгоритм Говарда Хиннанта.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const MON: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

pub struct Civil {
    pub y: i64,
    pub m: u32,
    pub d: u32,
    pub hh: u32,
    pub mm: u32,
    pub ss: u32,
    pub wd: usize,
}

pub fn civil(t: u64) -> Civil {
    let days = (t / 86400) as i64;
    let rem = (t % 86400) as u32;
    let (y, m, d) = civil_from_days(days);
    Civil {
        y,
        m,
        d,
        hh: rem / 3600,
        mm: (rem % 3600) / 60,
        ss: rem % 60,
        wd: ((days % 7 + 11) % 7) as usize, // day0=Thu(4): (days+4)%7, +7 на всякий
    }
}

/// RFC 5322 дата: Tue, 03 Nov 2026 12:34:56 +0000
pub fn rfc2822(t: u64) -> String {
    let c = civil(t);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        WD[c.wd], c.d, MON[(c.m - 1) as usize], c.y, c.hh, c.mm, c.ss
    )
}

/// IMAP INTERNALDATE: 03-Nov-2026 12:34:56 +0000
pub fn imap_date(t: u64) -> String {
    let c = civil(t);
    format!(
        "{:02}-{}-{:04} {:02}:{:02}:{:02} +0000",
        c.d, MON[(c.m - 1) as usize], c.y, c.hh, c.mm, c.ss
    )
}

/// "1-Jan-2026" | "1-Jan-2026 12:34:56" -> unix
pub fn parse_imap_date(s: &str) -> Option<u64> {
    let s = s.trim().trim_matches('"');
    let p: Vec<&str> = s.split_whitespace().collect();
    let dmy: Vec<&str> = p[0].split('-').collect();
    if dmy.len() != 3 {
        return None;
    }
    let d: u32 = dmy[0].parse().ok()?;
    let m = MON.iter().position(|x| x.eq_ignore_ascii_case(dmy[1]))? as u32 + 1;
    let y: i64 = dmy[2].parse().ok()?;
    let (hh, mm, ss) = if p.len() >= 2 {
        let t: Vec<&str> = p[1].split(':').collect();
        (
            t.first().and_then(|x| x.parse().ok()).unwrap_or(0u32),
            t.get(1).and_then(|x| x.parse().ok()).unwrap_or(0u32),
            t.get(2).and_then(|x| x.parse().ok()).unwrap_or(0u32),
        )
    } else {
        (0, 0, 0)
    };
    // обратный civil_from_days
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = (yy - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    Some((days as u64) * 86400 + hh as u64 * 3600 + mm as u64 * 60 + ss as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let long = vec![b'a'; 1000];
        assert_eq!(
            hex(&sha256(&long)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }
    #[test]
    fn b64_roundtrip() {
        for n in 0..40 {
            let d = urandom(n);
            assert_eq!(b64_decode(&b64_encode(&d)).unwrap(), d);
        }
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
    }
    #[test]
    fn dates() {
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(imap_date(1793692800), "03-Nov-2026 08:00:00 +0000");
        assert_eq!(parse_imap_date("3-Nov-2026").unwrap(), 1793664000);
    }
    #[test]
    fn pass_hash() {
        let h = hash_password("secret");
        assert!(verify_password("secret", &h));
        assert!(!verify_password("Secret", &h));
    }
}
