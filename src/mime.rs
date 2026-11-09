// mime.rs — свой MIME-парсер: заголовки, адреса, RFC 2047, multipart,
// BODYSTRUCTURE для IMAP, извлечение текста (для zent-ml).
use crate::util::b64_decode;

pub fn header_block(raw: &[u8]) -> (Vec<(String, String)>, usize) {
    // возвращает (headers unfolded, offset тела)
    let mut headers = Vec::new();
    let mut pos = 0usize;
    let mut cur: Option<(String, String)> = None;
    let max = raw.len().min(1 << 20); // заголовки до 1МБ
    while pos < max {
        let eol = match raw[pos..max].iter().position(|&b| b == b'\n') {
            Some(i) => pos + i,
            None => max,
        };
        let mut line = &raw[pos..=eol.min(raw.len() - 1).max(pos)];
        pos = eol + 1;
        if line.ends_with(b"\r\n") {
            line = &line[..line.len() - 2];
        } else if line.ends_with(b"\n") {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            break;
        }
        if (line[0] == b' ' || line[0] == b'\t') && cur.is_some() {
            // unfold
            let c = cur.as_mut().unwrap();
            c.1.push(' ');
            c.1.push_str(&String::from_utf8_lossy(line).trim().to_string());
        } else {
            if let Some(c) = cur.take() {
                headers.push(c);
            }
            let s = String::from_utf8_lossy(line).to_string();
            cur = match s.split_once(':') {
                Some((k, v)) => Some((k.trim().to_string(), v.trim().to_string())),
                None => Some((s.trim().to_string(), String::new())),
            };
        }
    }
    if let Some(c) = cur.take() {
        headers.push(c);
    }
    (headers, pos.min(raw.len()))
}

pub struct Msg<'a> {
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
}

impl<'a> Msg<'a> {
    pub fn parse(raw: &'a [u8]) -> Msg<'a> {
        let (headers, off) = header_block(raw);
        Msg {
            headers,
            body: &raw[off..],
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn subject_decoded(&self) -> String {
        self.get("Subject").map(rfc2047_decode).unwrap_or_default()
    }

    pub fn from_addr(&self) -> String {
        let raw = self.get("From").unwrap_or("");
        parse_address_list(raw)
            .first()
            .map(|(_, a)| a.clone())
            .unwrap_or_default()
    }

    pub fn date_header(&self) -> Option<u64> {
        self.get("Date").and_then(parse_rfc2822_date)
    }

    /// Структура части: (type, subtype, params)
    fn content_type(&self, hdrs: &[(String, String)]) -> (String, String, Vec<(String, String)>) {
        let ct = hdrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("text/plain");
        parse_content_type(ct)
    }

    fn transfer_encoding(&self, hdrs: &[(String, String)]) -> String {
        hdrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Transfer-Encoding"))
            .map(|(_, v)| v.trim().to_lowercase())
            .unwrap_or_default()
    }

    fn disposition(&self, hdrs: &[(String, String)]) -> Option<String> {
        hdrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
            .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_lowercase())
    }

    /// Рекурсивный обход: leaf-части с их заголовками и байтовым диапазоном.
    pub fn walk_parts<'m>(&'m self) -> Vec<Part<'m>> {
        let mut out = Vec::new();
        self.walk(self.headers.clone(), self.body, &mut out, 0);
        out
    }

    fn walk<'m>(
        &'m self,
        hdrs: Vec<(String, String)>,
        body: &'m [u8],
        out: &mut Vec<Part<'m>>,
        depth: usize,
    ) {
        if depth > 20 {
            return;
        }
        let (ctype, csub, params) = self.content_type(&hdrs);
        if ctype == "multipart" {
            if let Some(boundary) = params
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("boundary"))
                .map(|(_, v)| v.clone())
            {
                for (hb, pb) in split_multipart(body, &boundary) {
                    let (h, off) = header_block(hb);
                    self.walk(h, &pb[off..], out, depth + 1);
                    if out.len() > 500 {
                        break;
                    }
                }
                return;
            }
        }
        if ctype == "message" && csub == "rf822" || ctype == "message" && csub == "rfc822" {
            // вложенное сообщение: одна часть = само письмо
            let (h, off) = header_block(body);
            out.push(Part {
                headers: h.clone(),
                body: &body[off..],
                is_message: true,
                bytes: body.len(),
                lines: count_lines(&body[off..]),
            });
            // и его внутренности
            self.walk(h, &body[off..], out, depth + 1);
            return;
        }
        out.push(Part {
            headers: hdrs,
            body,
            is_message: false,
            bytes: body.len(),
            lines: count_lines(body),
        });
    }

    /// Текст письма для ML: subject + text/plain (+ text/html как fallback).
    pub fn extract_text(&self) -> String {
        let mut s = self.subject_decoded();
        s.push('\n');
        let parts = self.walk_parts();
        let mut plain: Option<String> = None;
        let mut html: Option<String> = None;
        for p in parts.iter() {
            if p.is_message {
                continue;
            }
            let (ct, cs, _) = self.content_type(&p.headers);
            if p.has_disposition() {
                continue; // attachment
            }
            if ct != "text" {
                continue;
            }
            let decoded = p.decoded_body();
            let txt = match cs.to_lowercase().as_str() {
                "koi8-r" => koi8r_to_utf8(&decoded),
                "windows-1251" | "cp1251" => cp1251_to_utf8(&decoded),
                _ => String::from_utf8_lossy(&decoded).to_string(),
            };
            if cs == "text/html" {
                let v = strip_html(&txt);
                if html.is_none() && !v.trim().is_empty() {
                    html = Some(v);
                }
            } else if plain.is_none() && !txt.trim().is_empty() {
                plain = Some(txt);
            }
        }
        s.push_str(&plain.or(html).unwrap_or_default());
        // обрежем до разумного
        s.chars().take(20000).collect()
    }
}

#[derive(Debug, Clone)]
pub struct Part<'a> {
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
    pub is_message: bool,
    pub bytes: usize,
    pub lines: usize,
}

impl<'a> Part<'a> {
    pub fn has_disposition(&self) -> bool {
        self.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
    }

    /// Декодированное тело (base64 / quoted-printable / raw).
    pub fn decoded_body(&self) -> Vec<u8> {
        let enc = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Transfer-Encoding"))
            .map(|(_, v)| v.trim().to_lowercase())
            .unwrap_or_default();
        match enc.as_str() {
            "base64" => b64_decode(&String::from_utf8_lossy(self.body).replace(char::is_whitespace, ""))
                .unwrap_or_else(|| self.body.to_vec()),
            "quoted-printable" => qp_decode(self.body),
            _ => self.body.to_vec(),
        }
    }
}

// --- multipart ---
pub fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<(&'a [u8], &'a [u8])> {
    let delim = format!("--{}", boundary);
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut starts: Vec<usize> = Vec::new();
    // найти строки-разделители
    let mut lines_at: Vec<(usize, usize)> = Vec::new(); // (line_start, after_eol)
    let mut i = 0usize;
    while i < body.len() {
        let eol = match body[i..].iter().position(|&b| b == b'\n') {
            Some(j) => i + j,
            None => body.len(),
        };
        let line = &body[i..=eol.min(body.len() - 1).max(i)];
        let trimmed = if line.ends_with(b"\r\n") {
            &line[..line.len() - 2]
        } else if line.ends_with(b"\n") {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed == delim.as_bytes() || trimmed == format!("--{}--", boundary).as_bytes() {
            lines_at.push((i, (eol + 1).min(body.len())));
        }
        i = eol + 1;
    }
    for w in lines_at.windows(2) {
        starts.push(w[0].1);
        pos = w[1].0;
    }
    for (idx, &s) in starts.iter().enumerate() {
        let e = lines_at.get(idx + 1).map(|x| x.0).unwrap_or(body.len());
        if e > s {
            out.push((&body[s..e], &body[s..e]));
        }
    }
    // отдаём пары (raw part incl headers); упрощённо: одна и та же ссылка дважды
    out.into_iter().map(|(a, b)| (a, b)).collect()
}

fn count_lines(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

// --- content-type ---
pub fn parse_content_type(ct: &str) -> (String, String, Vec<(String, String)>) {
    let mut it = ct.split(';');
    let main = it.next().unwrap_or("text/plain").trim().to_lowercase();
    let (ctype, csub) = match main.split_once('/') {
        Some((a, b)) => (a.to_string(), b.trim().to_string()),
        None => (main, String::from("plain")),
    };
    let mut params = Vec::new();
    for p in it {
        let p = p.trim();
        if let Some((k, v)) = p.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            params.push((k.trim().to_lowercase(), v));
        }
    }
    (ctype, csub, params)
}

// --- quoted-printable ---
pub fn qp_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let s = b;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        match c {
            b'=' if i + 2 < s.len() => {
                let h = |x: u8| (x as char).to_digit(16);
                if let (Some(a), Some(bb)) = (h(s[i + 1]), h(s[i + 2])) {
                    out.push((a * 16 + bb) as u8);
                    i += 3;
                } else if s[i + 1] == b'\n' || (s[i + 1] == b'\r' && i + 2 < s.len() && s[i + 2] == b'\n') {
                    // мягкий перенос
                    i += if s[i + 1] == b'\n' { 2 } else { 3 };
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

// --- RFC 2047 (=?utf-8?B?...?= / Q) ---
pub fn rfc2047_decode(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut last_was_encoded = false;
    while i < b.len() {
        if b[i] == b'=' && i + 1 < b.len() && b[i + 1] == b'?' {
            if let Some(res) = decode_one_word(&b[i..]) {
                let (txt, consumed) = res;
                out.push_str(&txt);
                i += consumed;
                last_was_encoded = true;
                continue;
            }
        }
        let ch_len = utf8_len(b[i]);
        let chunk = &s[i..(i + ch_len).min(s.len())];
        if last_was_encoded && chunk == " " {
            // пробел между двумя encoded-words не значим
            last_was_encoded = false;
            i += 1;
            continue;
        }
        out.push_str(chunk);
        last_was_encoded = false;
        i += ch_len;
    }
    out
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

fn decode_one_word(b: &[u8]) -> Option<(String, usize)> {
    // =?charset?enc?data?= — закрывающий "?=" ищем целиком (в data есть '=' паддинг)
    let end = b[2..]
        .windows(2)
        .position(|w| w == b"?=")
        .map(|p| p + 2 + 2)?;
    let word = &b[2..end - 2];
    let parts: Vec<&[u8]> = word.split(|&x| x == b'?').collect();
    if parts.len() != 3 {
        return None;
    }
    let charset = String::from_utf8_lossy(parts[0]).to_lowercase();
    let enc = parts[1][0].to_ascii_uppercase();
    let data = parts[2];
    let decoded = match enc {
        b'B' => b64_decode(&String::from_utf8_lossy(data))?,
        b'Q' => {
            let mut tmp = Vec::with_capacity(data.len());
            let mut i = 0usize;
            while i < data.len() {
                match data[i] {
                    b'_' => {
                        tmp.push(b' ');
                        i += 1;
                    }
                    b'=' if i + 2 < data.len() => {
                        let h = |x: u8| (x as char).to_digit(16);
                        tmp.push((h(data[i + 1])? * 16 + h(data[i + 2])?) as u8);
                        i += 3;
                    }
                    c => {
                        tmp.push(c);
                        i += 1;
                    }
                }
            }
            tmp
        }
        _ => return None,
    };
    let txt = match charset.as_str() {
        "koi8-r" | "koi8" => koi8r_to_utf8(&decoded),
        "windows-1251" | "cp1251" | "windows-1252" if charset.contains("1251") => {
            cp1251_to_utf8(&decoded)
        }
        _ => String::from_utf8_lossy(&decoded).to_string(),
    };
    Some((txt, end + 1))
}

// --- адреса ---
/// Список адресов: "Name <a@b>, c@d" -> [(Name, a@b)]
pub fn parse_address_list(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut items: Vec<String> = Vec::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                cur.push(c);
                while let Some(c2) = chars.next() {
                    cur.push(c2);
                    if c2 == '"' {
                        break;
                    }
                }
            }
            '<' => {
                depth += 1;
                cur.push(c);
            }
            '>' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                items.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        items.push(cur);
    }
    for item in items {
        let item = rfc2047_decode(&item);
        if let Some(lt) = item.find('<') {
            if let Some(gt) = item.find('>') {
                let addr = item[lt + 1..gt].trim().to_string();
                let name = item[..lt].trim().trim_matches('"').trim().to_string();
                if !addr.is_empty() {
                    out.push((name, addr));
                }
                continue;
            }
        }
        let addr = item.trim().trim_matches('"').to_string();
        if addr.contains('@') {
            out.push((String::new(), addr));
        }
    }
    out
}

/// Адрес для IMAP ENVELOPE: (("name" NIL "mailbox" "host"))
pub fn imap_addr(raw: &str) -> String {
    let list = parse_address_list(raw);
    if list.is_empty() {
        return "NIL".into();
    }
    let mut parts = Vec::new();
    for (name, addr) in &list {
        let (mb, host) = match addr.rsplit_once('@') {
            Some((m, h)) => (m, h),
            None => (addr.as_str(), "NIL"),
        };
        parts.push(format!(
            "({} NIL \"{}\" \"{}\")",
            imap_string(name),
            imap_escape(mb),
            imap_escape(host)
        ));
    }
    format!("({})", parts.join(""))
}

pub fn imap_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn imap_string(s: &str) -> String {
    if s.is_empty() {
        return "NIL".into();
    }
    format!("\"{}\"", imap_escape(s))
}

// --- BODYSTRUCTURE ---
pub fn bodystructure(raw: &[u8], extended: bool) -> String {
    let msg = Msg::parse(raw);
    bs_section(&msg.headers, msg.body, &msg, extended, true)
}

fn bs_section(
    hdrs: &[(String, String)],
    body: &[u8],
    msg: &Msg,
    extended: bool,
    top: bool,
) -> String {
    let (ctype, csub, params) = msg.content_type(hdrs);
    if ctype == "multipart" {
        let mut out = String::from("(");
        if let Some(boundary) = params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("boundary"))
            .map(|(_, v)| v.clone())
        {
            for (hb, pb) in split_multipart(body, &boundary) {
                let (h, off) = header_block(hb);
                out.push_str(&bs_section(&h, &pb[off..], msg, extended, false));
                if out.len() > 100_000 {
                    break;
                }
            }
        } else {
            out.push_str(&bs_section(hdrs, body, msg, extended, false));
        }
        out.push_str(&format!(" \"{}\"", csub.to_uppercase()));
        if extended {
            out.push_str(&bs_ext(hdrs, params));
        }
        out.push(')');
        return out;
    }
    // leaf
    let enc = hdrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Transfer-Encoding"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| "7bit".into());
    let cid = hdrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-ID"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let desc = hdrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Description"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let disp = hdrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
        .map(|(_, v)| v.trim().to_string());
    let lines = count_lines(body);
    let mut out = format!(
        "(\"{}\" \"{}\"{} NIL NIL \"{}\" {} {}",
        ctype.to_uppercase(),
        csub.to_uppercase(),
        bs_params(&params),
        enc.to_uppercase(),
        body.len(),
        if ctype == "text" { lines.to_string() } else { "NIL".into() }
    );
    if extended {
        out.push_str(&format!(
            " {} {} {}",
            imap_string(&cid),
            imap_string(&desc),
            imap_string(&enc)
        ));
        if let Some(d) = disp {
            let mut it = d.splitn(2, ';');
            let kind = it.next().unwrap_or("").trim().to_lowercase();
            let dparams: Vec<(String, String)> = it
                .next()
                .map(|rest| {
                    rest.split(';')
                        .filter_map(|p| p.split_once('='))
                        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().trim_matches('"').to_string()))
                        .collect()
                })
                .unwrap_or_default();
            out.push_str(&format!("(\"{}\"{})", kind.to_uppercase(), bs_params(&dparams)));
        } else {
            out.push_str(" NIL");
        }
        out.push_str(" NIL"); // language
    }
    out.push(')');
    let _ = (top, params);
    out
}

fn bs_params(params: &[(String, String)]) -> String {
    if params.is_empty() {
        return " NIL".into();
    }
    let mut s = String::from(" (");
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("\"{}\" \"{}\"", k.to_uppercase(), imap_escape(v)));
    }
    s.push(')');
    s
}

fn bs_ext(hdrs: &[(String, String)], params: Vec<(String, String)>) -> String {
    let disp = hdrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
        .map(|(_, v)| v.trim().to_string());
    let mut out = bs_params(&params);
    out.push_str(" NIL NIL"); // id, description
    if let Some(d) = disp {
        let mut it = d.splitn(2, ';');
        let kind = it.next().unwrap_or("").trim().to_lowercase();
        let dparams: Vec<(String, String)> = it
            .next()
            .map(|rest| {
                rest.split(';')
                    .filter_map(|p| p.split_once('='))
                    .map(|(k, v)| (k.trim().to_lowercase(), v.trim().trim_matches('"').to_string()))
                    .collect()
            })
            .unwrap_or_default();
        out.push_str(&format!(" (\"{}\"{})", kind.to_uppercase(), bs_params(&dparams)));
    } else {
        out.push_str(" NIL");
    }
    out.push_str(" NIL"); // language
    out
}

// --- RFC 2822 Date ---
pub fn parse_rfc2822_date(s: &str) -> Option<u64> {
    let s = s.trim();
    // Tue, 03 Nov 2026 12:34:56 +0000 | с уточнениями зон
    let after_comma = s.split_once(',').map(|(_, r)| r.trim()).unwrap_or(s);
    let p: Vec<&str> = after_comma.split_whitespace().collect();
    if p.len() < 4 {
        return None;
    }
    let d: u32 = p[0].trim_start_matches('0').parse().ok()?;
    const MON: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let m = MON.iter().position(|x| p[1].to_lowercase().starts_with(x))? as u32 + 1;
    let y: i64 = {
        let mut y: i64 = p[2].parse().ok()?;
        if y < 100 {
            y += if y < 50 { 2000 } else { 1900 };
        }
        y
    };
    let t: Vec<&str> = p[3].split(':').collect();
    let hh: u64 = t.first().and_then(|x| x.parse().ok()).unwrap_or(0);
    let mm: u64 = t.get(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    let ss: u64 = t.get(2).and_then(|x| x.parse().ok()).unwrap_or(0);
    // зона
    let mut offset: i64 = 0;
    if let Some(z) = p.get(4) {
        offset = match *z {
            "+0000" | "-0000" | "UT" | "GMT" | "UTC" => 0,
            "EST" => -5 * 3600,
            "EDT" => -4 * 3600,
            "CST" => -6 * 3600,
            "CDT" => -5 * 3600,
            "MST" => -7 * 3600,
            "MDT" => -6 * 3600,
            "PST" => -8 * 3600,
            "PDT" => -7 * 3600,
            _ => {
                let sign = if z.starts_with('-') { -1i64 } else { 1 };
                let dz: i64 = z.trim_start_matches(['+', '-']).parse().ok()?;
                sign * (dz / 100) * 3600 + sign * (dz % 100) * 60
            }
        };
    }
    // days from civil (обратный civil_from_days)
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = (yy - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    let secs = (days as i64) * 86400 + (hh * 3600 + mm * 60 + ss) as i64 - offset;
    Some(secs.max(0) as u64)
}

// --- прочее ---
pub fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

pub fn koi8r_to_utf8(b: &[u8]) -> String {
    const T: [char; 140] = [
        'Ё','ё','А','Б','В','Г','Д','Е','Ж','З','И','Й','К','Л','М','Н','О','П','Р','С','Т','У',
        'Ф','Х','Ц','Ч','Ш','Щ','Ъ','Ы','Ь','Э','Ю','Я','а','б','в','г','д','е','ж','з','и','й',
        'к','л','м','н','о','п','р','с','т','у','ф','х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я',
        '│','┤','║','╗','╝','┐','└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','╧',
        '╨','╤','╥','╙','╘','╒','╓','╫','╪','┘','┌','█','▄','▌','▐','▀','α','β','γ','δ','ε','ζ',
        'η','θ','ι','κ','λ','μ','ν','ξ','ο','π','ρ','σ','τ','υ','φ','χ','ψ','ω','∙','√','≈','≥',
        ' ','÷','°','·','·','√','ⁿ','²',
    ];
    b.iter()
        .map(|&c| if c < 0x80 { c as char } else { T[(c - 0x80) as usize] })
        .collect()
}

pub fn cp1251_to_utf8(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c < 0x80 {
                c as char
            } else if (0xC0..=0xFF).contains(&c) {
                char::from_u32(0x0410u32 + (c - 0xC0) as u32).unwrap_or('�')
            } else {
                match c {
                    0xA8 => 'Ё',
                    0xB8 => 'ё',
                    0xB9 => '№',
                    0xAB => '«',
                    0xBB => '»',
                    0x96 => '–',
                    0x97 => '—',
                    0x91 => '‘',
                    0x92 => '’',
                    0x93 => '“',
                    0x94 => '”',
                    0x85 => '…',
                    _ => '�',
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIL: &[u8] = b"From: Ivan <ivan@rival-afk.com>\r\nTo: bob@example.com, X <x@y.z>\r\nSubject: =?utf-8?B?0J/RgNC40LLQtdGC?=\r\nContent-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82 world\r\n--BB--\r\n";

    #[test]
    fn headers_and_parts() {
        let m = Msg::parse(MAIL);
        assert_eq!(m.get("From").unwrap(), "Ivan <ivan@rival-afk.com>");
        assert_eq!(m.subject_decoded(), "Привет");
        let parts = m.walk_parts();
        assert_eq!(parts.len(), 1);
        let body = parts[0].decoded_body();
        assert_eq!(String::from_utf8(body).unwrap(), "Привет world\r\n");
    }

    #[test]
    fn addr_parse() {
        let l = parse_address_list("Bob <bob@a.b>, x@y.z, \"S, V\" <s@v.io>");
        assert_eq!(l.len(), 3);
        assert_eq!(l[0], ("Bob".into(), "bob@a.b".into()));
        assert_eq!(l[2].1, "s@v.io");
    }

    #[test]
    fn date_parse() {
        assert_eq!(parse_rfc2822_date("Thu, 01 Jan 1970 00:00:00 +0000"), Some(0));
        let t = parse_rfc2822_date("Tue, 03 Nov 2026 08:00:00 +0000").unwrap();
        assert_eq!(crate::util::imap_date(t), "03-Nov-2026 08:00:00 +0000");
    }

    #[test]
    fn bodystructure_ok() {
        let bs = bodystructure(MAIL, true);
        assert!(bs.contains("\"MIXED\""), "{bs}");
        assert!(bs.contains("\"TEXT\""), "{bs}");
    }

    #[test]
    fn qp() {
        // =3D -> '=', =20 -> ' ', =0A -> '\n', мягкий перенос '=\\r\\n' исчезает
        assert_eq!(qp_decode(b"a=3Db\r\nc=20=0A"), b"a=b\r\nc \n");
        assert_eq!(qp_decode(b"x=\r\ny"), b"xy");
        assert_eq!(qp_decode(b"p="), b"p=");
    }
}
