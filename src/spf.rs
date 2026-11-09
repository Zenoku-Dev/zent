// spf.rs — SPF-чекер (RFC 7208, достаточный subset).
//  - механизмы: ip4 ip6 a mx include exists all, модификатор redirect=
//  - квалифаеры + - ~ ?, лимиты 10 DNS-lookup / 10 include (глубина)
//  - DNS через dns.rs, всё в spawn_blocking (блокирующий UDP-резолвер)
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use crate::dns;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfVerdict {
    Pass,
    Fail,
    Softfail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl SpfVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpfVerdict::Pass => "pass",
            SpfVerdict::Fail => "fail",
            SpfVerdict::Softfail => "softfail",
            SpfVerdict::Neutral => "neutral",
            SpfVerdict::None => "none",
            SpfVerdict::TempError => "temperror",
            SpfVerdict::PermError => "permerror",
        }
    }
}

const MAX_LOOKUPS: u32 = 10;
const MAX_DEPTH: u32 = 10;

struct State {
    ip: IpAddr,
    lookups: u32,
}

/// Проверка SPF. sender — адрес из MAIL FROM (может быть пустым — тогда helo).
/// Возвращает (вердикт, домен, по которому проверяли).
pub async fn check(ip: IpAddr, helo: &str, sender: &str) -> (SpfVerdict, String) {
    let domain = if sender.trim().is_empty() {
        helo.trim().trim_end_matches('.').to_lowercase()
    } else if let Some((_, d)) = sender.rsplit_once('@') {
        d.trim().trim_end_matches('.').to_lowercase()
    } else {
        sender.trim().trim_end_matches('.').to_lowercase()
    };
    if domain.is_empty() {
        return (SpfVerdict::None, domain);
    }
    let mut st = State { ip, lookups: 0 };
    let v = check_host(&mut st, &domain, 0).await;
    (v, domain)
}

async fn txt(domain: &str) -> Vec<String> {
    let d = domain.to_string();
    tokio::task::spawn_blocking(move || dns::txt_lookup(&d))
        .await
        .unwrap_or_default()
}

async fn a(host: &str) -> Option<Ipv4Addr> {
    let h = host.to_string();
    tokio::task::spawn_blocking(move || dns::a_lookup(&h))
        .await
        .unwrap_or(None)
}

async fn mx(domain: &str) -> Vec<String> {
    let d = domain.to_string();
    tokio::task::spawn_blocking(move || dns::mx_lookup(&d))
        .await
        .unwrap_or_default()
}

fn is_spf_record(t: &str) -> bool {
    let lower = t.trim().to_ascii_lowercase();
    lower == "v=spf1" || lower.starts_with("v=spf1 ")
}

async fn check_host_inner(st: &mut State, domain: &str, depth: u32) -> SpfVerdict {
    if depth > MAX_DEPTH {
        return SpfVerdict::PermError;
    }
    let mut recs: Vec<String> = txt(domain).await.into_iter().filter(|t| is_spf_record(t)).collect();
    if recs.len() > 1 {
        return SpfVerdict::PermError; // несколько v=spf1 записей — запрещено
    }
    let rec = match recs.pop() {
        Some(r) => r,
        None => return SpfVerdict::None,
    };
    let mut redirect: Option<String> = None;
    for term in rec.split_whitespace().skip(1) {
        // модификатор name=value (имя без ':' и '/')
        if let Some((name, val)) = term.split_once('=') {
            if !name.contains(':') && !name.contains('/') {
                if name.eq_ignore_ascii_case("redirect") {
                    redirect = Some(val.trim().trim_end_matches('.').to_string());
                }
                continue; // exp= и прочее игнорируем
            }
        }
        let (qual, mech) = match term.as_bytes().first() {
            Some(b'-') => ('-', &term[1..]),
            Some(b'~') => ('~', &term[1..]),
            Some(b'?') => ('?', &term[1..]),
            Some(b'+') => ('+', &term[1..]),
            _ => ('+', term),
        };
        match eval_mech(st, mech, domain, depth).await {
            Ok(true) => {
                return match qual {
                    '-' => SpfVerdict::Fail,
                    '~' => SpfVerdict::Softfail,
                    '?' => SpfVerdict::Neutral,
                    _ => SpfVerdict::Pass,
                };
            }
            Ok(false) => {}
            Err(v) => return v,
        }
    }
    if let Some(rd) = redirect {
        if rd.is_empty() {
            return SpfVerdict::PermError;
        }
        st.lookups += 1;
        if st.lookups > MAX_LOOKUPS {
            return SpfVerdict::TempError;
        }
        return match check_host(st, &rd, depth + 1).await {
            SpfVerdict::None => SpfVerdict::PermError, // redirect на домен без SPF
            v => v,
        };
    }
    SpfVerdict::Neutral
}

/// Обёртка с Box::pin — взаимная рекурсия check_host <-> eval_mech.
fn check_host<'a>(st: &'a mut State, domain: &'a str, depth: u32) -> Pin<Box<dyn Future<Output = SpfVerdict> + Send + 'a>> {
    Box::pin(check_host_inner(st, domain, depth))
}

async fn eval_mech(st: &mut State, mech: &str, cur: &str, depth: u32) -> Result<bool, SpfVerdict> {
    let (name, arg) = match mech.split_once(':') {
        Some((n, a)) => (n, a),
        None => (mech, ""),
    };
    match name.to_ascii_lowercase().as_str() {
        "all" => Ok(true),
        "ip4" => {
            let (addr, cidr) = split_cidr(arg, 32);
            let net: Ipv4Addr = addr.parse().map_err(|_| SpfVerdict::PermError)?;
            Ok(match st.ip {
                IpAddr::V4(ip) => v4_match(ip, net, cidr),
                IpAddr::V6(_) => false,
            })
        }
        "ip6" => {
            let (addr, cidr) = split_cidr(arg, 128);
            let net: Ipv6Addr = addr.parse().map_err(|_| SpfVerdict::PermError)?;
            Ok(match st.ip {
                IpAddr::V6(ip) => v6_match(ip, net, cidr),
                IpAddr::V4(_) => false,
            })
        }
        "a" => {
            st.lookups += 1;
            if st.lookups > MAX_LOOKUPS {
                return Err(SpfVerdict::TempError);
            }
            let (dom, cidr) = split_cidr(arg, 32);
            let dom = if dom.is_empty() { cur.to_string() } else { dom.to_string() };
            Ok(match a(&dom).await {
                Some(ip) => ip4_client(st.ip, ip, cidr),
                None => false,
            })
        }
        "mx" => {
            st.lookups += 1;
            if st.lookups > MAX_LOOKUPS {
                return Err(SpfVerdict::TempError);
            }
            let (dom, cidr) = split_cidr(arg, 32);
            let dom = if dom.is_empty() { cur.to_string() } else { dom.to_string() };
            for host in mx(&dom).await {
                st.lookups += 1;
                if st.lookups > MAX_LOOKUPS {
                    return Err(SpfVerdict::TempError);
                }
                if let Some(ip) = a(&host).await {
                    if ip4_client(st.ip, ip, cidr) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        "include" => {
            if arg.is_empty() {
                return Err(SpfVerdict::PermError);
            }
            st.lookups += 1;
            if st.lookups > MAX_LOOKUPS {
                return Err(SpfVerdict::TempError);
            }
            let dom = arg.trim().trim_end_matches('.').to_string();
            match check_host(st, &dom, depth + 1).await {
                SpfVerdict::Pass => Ok(true),
                SpfVerdict::Fail | SpfVerdict::Softfail | SpfVerdict::Neutral | SpfVerdict::None => Ok(false),
                SpfVerdict::TempError => Err(SpfVerdict::TempError),
                SpfVerdict::PermError => Err(SpfVerdict::PermError),
            }
        }
        "exists" => {
            if arg.is_empty() {
                return Err(SpfVerdict::PermError);
            }
            st.lookups += 1;
            if st.lookups > MAX_LOOKUPS {
                return Err(SpfVerdict::TempError);
            }
            Ok(a(arg.trim()).await.is_some())
        }
        _ => Err(SpfVerdict::PermError),
    }
}

// (значение, cidr); cidr==0 означает "полная длина"
fn split_cidr(s: &str, full: u8) -> (&str, u8) {
    match s.rsplit_once('/') {
        Some((a, c)) => (a, c.parse::<u8>().unwrap_or(full)),
        None => (s, 0),
    }
}

fn ip4_client(client: IpAddr, a: Ipv4Addr, cidr: u8) -> bool {
    match client {
        IpAddr::V4(c) => v4_match(c, a, cidr),
        IpAddr::V6(_) => false,
    }
}

fn v4_match(ip: Ipv4Addr, net: Ipv4Addr, cidr: u8) -> bool {
    let cidr = cidr as u32;
    let m = match cidr {
        0 => 0, // /0 — совпадает всё
        32 => u32::MAX,
        n => u32::MAX << (32 - n),
    };
    u32::from(ip) & m == u32::from(net) & m
}

fn v6_match(ip: Ipv6Addr, net: Ipv6Addr, cidr: u8) -> bool {
    let cidr = cidr as u32;
    let a = u128::from_be_bytes(ip.octets());
    let b = u128::from_be_bytes(net.octets());
    let m = match cidr {
        0 => 0,
        128 => u128::MAX,
        n => u128::MAX << (128 - n),
    };
    a & m == b & m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_match() {
        let ip: Ipv4Addr = "192.0.2.65".parse().unwrap();
        let net: Ipv4Addr = "192.0.2.0".parse().unwrap();
        assert!(v4_match(ip, net, 24));
        assert!(!v4_match(ip, net, 32));
        assert!(v4_match(ip, net, 0)); // полная длина
        let ip6: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let net6: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(v6_match(ip6, net6, 32));
        assert!(!v6_match(ip6, net6, 48));
    }

    #[test]
    fn qual_parse() {
        assert!(is_spf_record("v=spf1 mx -all"));
        assert!(!is_spf_record("v=spf10 mx"));
    }
}
