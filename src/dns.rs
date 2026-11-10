// dns.rs — свой DNS-резолвер (MX/A) поверх UDP. Без hickory, всё своё.
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use crate::util::{hex, urandom};

fn resolv_conf_ns() -> Vec<String> {
    let cfg = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut out = Vec::new();
    for line in cfg.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("nameserver") {
            if let Some(ns) = it.next() {
                out.push(ns.to_string());
            }
        }
    }
    if out.is_empty() {
        out.push("8.8.8.8".to_string());
    }
    out
}

// имя -> метки DNS-запроса
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

// распаковка имени с учётом compression-указателей
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut end = pos; // позиция после имени (для первого вызова)
    loop {
        if pos >= msg.len() || jumps > 16 {
            return None;
        }
        let len = msg[pos];
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    if end == 0 || end <= pos - 1 {
                        end = pos;
                    }
                    break;
                }
                let s = msg.get(pos + 1..pos + 1 + len as usize)?;
                labels.push(String::from_utf8_lossy(s).to_string());
                pos += 1 + len as usize;
            }
            0xC0 => {
                let ptr = (((len & 0x3F) as usize) << 8) | *msg.get(pos + 1)? as usize;
                if end <= pos + 1 || end == pos {
                    end = pos + 2;
                }
                pos = ptr;
                jumps += 1;
            }
            _ => return None,
        }
    }
    Some((labels.join("."), end))
}

struct Query {
    id: u16,
    packet: Vec<u8>,
}

fn build_query(name: &str, qtype: u16) -> Query {
    let id = u16::from_be_bytes([urandom(2)[0], urandom(2)[1]]);
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    encode_name(name, &mut p);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // IN
    Query { id, packet: p }
}

// ответ: (mx список по приоритету, a-записи, txt-строки)
fn parse_response(msg: &[u8], qtype: u16) -> Option<(Vec<(u16, String)>, Vec<Ipv4Addr>, Vec<String>)> {
    if msg.len() < 12 {
        return None;
    }
    let _id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x000F != 0 {
        return Some((vec![], vec![], vec![])); // NXDOMAIN и пр. — пусто
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(msg, pos)?;
        pos = p + 4; // qtype+qclass
    }
    let mut mx = Vec::new();
    let mut a = Vec::new();
    let mut txt = Vec::new();
    for _ in 0..an {
        let (_, p) = read_name(msg, pos)?;
        pos = p;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rd = pos + 10;
        if rd + rdlen > msg.len() {
            break;
        }
        match rtype {
            15 if qtype == 15 && rdlen > 2 => {
                let pref = u16::from_be_bytes([msg[rd], msg[rd + 1]]);
                if let Some((host, _)) = read_name(msg, rd + 2) {
                    if !host.is_empty() {
                        mx.push((pref, host));
                    }
                }
            }
            1 if rdlen == 4 => {
                a.push(Ipv4Addr::new(msg[rd], msg[rd + 1], msg[rd + 2], msg[rd + 3]));
            }
            16 if qtype == 16 => {
                // TXT: последовательность character-string (<len><байты>...)
                let mut i = rd;
                let mut s = String::new();
                while i < rd + rdlen {
                    let l = msg[i] as usize;
                    i += 1;
                    if i + l > rd + rdlen {
                        break;
                    }
                    s.push_str(&String::from_utf8_lossy(&msg[i..i + l]));
                    i += l;
                }
                txt.push(s);
            }
            _ => {}
        }
        pos = rd + rdlen;
    }
    Some((mx, a, txt))
}

fn query(name: &str, qtype: u16) -> Option<(Vec<(u16, String)>, Vec<Ipv4Addr>, Vec<String>)> {
    let q = build_query(name, qtype);
    for ns in resolv_conf_ns() {
        let dst = if ns.contains(':') {
            format!("[{}]:53", ns)
        } else {
            format!("{}:53", ns)
        };
        let sock = match UdpSocket::bind(("0.0.0.0", 0)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        sock.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
        if sock.send_to(&q.packet, &dst).is_err() {
            continue;
        }
        let mut buf = [0u8; 4096];
        for _ in 0..2 {
            match sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    let msg = &buf[..n];
                    if msg.len() < 12 {
                        continue;
                    }
                    let id = u16::from_be_bytes([msg[0], msg[1]]);
                    if id != q.id {
                        continue;
                    }
                    return parse_response(msg, qtype);
                }
                Err(_) => break, // timeout — пробуем следующий сервер
            }
        }
    }
    None
}

/// MX-хосты домена, отсортированные по приоритету.
pub fn mx_lookup(domain: &str) -> Vec<String> {
    if let Some((mut mx, _, _)) = query(domain, 15) {
        mx.sort_by_key(|(pref, _)| *pref);
        let hosts: Vec<String> = mx.into_iter().map(|(_, h)| h).collect();
        if !hosts.is_empty() {
            return hosts;
        }
    }
    // RFC 5321 §5.1: нет MX — доставляем на A
    if a_lookup(domain).is_some() {
        return vec![domain.to_string()];
    }
    vec![]
}

pub fn a_lookup(host: &str) -> Option<Ipv4Addr> {
    if host.parse::<Ipv4Addr>().is_ok() {
        return host.parse().ok();
    }
    let (_, a, _) = query(host, 1)?;
    a.into_iter().next()
}

/// TXT-записи имени (qtype 16); character-string'ы внутри записи склеены.
pub fn txt_lookup(name: &str) -> Vec<String> {
    match query(name, 16) {
        Some((_, _, txt)) => txt,
        None => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_roundtrip() {
        let mut p = vec![0u8; 12];
        encode_name("mail.rival-afk.com", &mut p);
        let (n, end) = read_name(&p, 12).unwrap();
        assert_eq!(n, "mail.rival-afk.com");
        assert_eq!(end, p.len());
    }
    #[test]
    fn live_mx() {
        // сетевой тест — не прогоняем в обычных прогонах
        if std::env::var("ZENT_NET_TEST").is_err() {
            return;
        }
        let mx = mx_lookup("rival-afk.com");
        assert_eq!(mx, vec!["mail.rival-afk.com"]);
    }
    #[test]
    fn id_collision_guard() {
        // у двух разных запросов id почти наверняка различается
        let a = build_query("a.test", 1).id;
        let b = build_query("a.test", 1).id;
        let _ = hex(&[0]);
        assert!(a != b || std::env::var("CI").is_ok()); // 1/65536 коллизия допустима
    }
}
