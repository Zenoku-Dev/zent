// maildir.rs — Maildir-хранилище (tmp/new/cur), своё.
//  - флаги в имени файла: <uid>.M<sec>S<usec>.zent:2,<DFPRST>
//  - каталоги: store/<user>/ (INBOX), store/<user>/.<Folder>/ (Maildir++)
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::util::now;

#[derive(Debug, Clone)]
pub struct MsgMeta {
    pub uid: u64,
    pub name: String,
    pub flags: String, // символы DFPRST
    pub size: u64,
    pub mtime: u64,
}

#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

fn sanitize_email(e: &str) -> String {
    e.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Имя каталога ящика: INBOX/"" -> корень юзера, остальное -> .Name
pub fn folder_dir(base: &Path, folder: &str) -> PathBuf {
    let f = normalize_folder(folder);
    if f.is_empty() {
        base.to_path_buf()
    } else {
        base.join(format!(".{f}"))
    }
}

pub fn normalize_folder(folder: &str) -> String {
    let mut f = folder.trim().trim_matches('/').to_string();
    if f.eq_ignore_ascii_case("inbox") {
        return String::new();
    }
    if let Some(rest) = f.strip_prefix("INBOX/") {
        f = rest.to_string();
    }
    f.trim_start_matches('.').to_string()
}

/// Валидация имени папки (CREATE/APPEND): только безопасные символы.
pub fn valid_folder(f: &str) -> bool {
    !f.is_empty()
        && f.len() < 128
        && f.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
        && !f.starts_with('.')
        && !f.ends_with('.')
        && !f.contains("..")
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Store {
        Store { root: root.into() }
    }

    pub fn user_dir(&self, email: &str) -> PathBuf {
        self.root.join(sanitize_email(email))
    }

    pub fn exists(&self, email: &str) -> bool {
        self.user_dir(email).join("cur").is_dir()
    }

    pub fn ensure_user(&self, email: &str) -> std::io::Result<PathBuf> {
        let base = self.user_dir(email);
        for sub in ["tmp", "new", "cur"] {
            std::fs::create_dir_all(base.join(sub))?;
        }
        Ok(base)
    }

    pub fn remove_user(&self, email: &str) -> std::io::Result<()> {
        let d = self.user_dir(email);
        if d.exists() {
            std::fs::remove_dir_all(d)?;
        }
        Ok(())
    }

    fn meta_file(base: &Path) -> PathBuf {
        base.join("zent-uid")
    }

    fn read_meta(base: &Path) -> (u64, u64) {
        // (uidvalidity, nextuid)
        if let Ok(raw) = std::fs::read_to_string(Self::meta_file(base)) {
            let mut it = raw.split_whitespace();
            let uv = it.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| now());
            let un = it.next().and_then(|s| s.parse().ok()).unwrap_or(1);
            (uv, un)
        } else {
            (now().max(1), 1)
        }
    }

    fn write_meta(base: &Path, uv: u64, un: u64) -> std::io::Result<()> {
        let mut f = std::fs::File::create(Self::meta_file(base))?;
        writeln!(f, "{uv} {un}")?;
        Ok(())
    }

    pub fn uidvalidity(&self, email: &str, folder: &str) -> u64 {
        let d = folder_dir(&self.user_dir(email), folder);
        Self::read_meta(&d).0
    }

    pub fn uidnext(&self, email: &str, folder: &str) -> u64 {
        let d = folder_dir(&self.user_dir(email), folder);
        Self::read_meta(&d).1
    }

    pub fn create_folder(&self, email: &str, folder: &str) -> std::io::Result<bool> {
        let base = self.ensure_user(email)?;
        let d = folder_dir(&base, folder);
        if d.exists() {
            return Ok(false);
        }
        for sub in ["tmp", "new", "cur"] {
            std::fs::create_dir_all(d.join(sub))?;
        }
        Self::write_meta(&d, now().max(1), 1)?;
        Ok(true)
    }

    pub fn delete_folder(&self, email: &str, folder: &str) -> std::io::Result<bool> {
        if normalize_folder(folder).is_empty() {
            return Err(std::io::Error::other("cannot delete INBOX"));
        }
        let d = folder_dir(&self.user_dir(email), folder);
        if !d.exists() {
            return Ok(false);
        }
        std::fs::remove_dir_all(d)?;
        Ok(true)
    }

    pub fn rename_folder(&self, email: &str, from: &str, to: &str) -> std::io::Result<bool> {
        if normalize_folder(from).is_empty() {
            return Err(std::io::Error::other("cannot rename INBOX"));
        }
        let base = self.user_dir(email);
        let src = folder_dir(&base, from);
        let dst = folder_dir(&base, to);
        if !src.exists() || dst.exists() {
            return Ok(false);
        }
        for sub in ["tmp", "new", "cur"] {
            std::fs::create_dir_all(dst.join(sub))?;
        }
        for sub in ["new", "cur"] {
            if let Ok(entries) = std::fs::read_dir(src.join(sub)) {
                for e in entries.flatten() {
                    let p = dst.join(sub).join(e.file_name());
                    std::fs::rename(e.path(), p)?;
                }
            }
        }
        let (uv, un) = Self::read_meta(&src);
        Self::write_meta(&dst, uv, un)?;
        std::fs::remove_dir_all(&src)?;
        Ok(true)
    }

    pub fn list_folders(&self, email: &str) -> Vec<String> {
        let mut out = vec![String::new()];
        let base = self.user_dir(email);
        if let Ok(entries) = std::fs::read_dir(&base) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(f) = name.strip_prefix('.') {
                    if e.path().join("cur").is_dir() {
                        out.push(f.to_string());
                    }
                }
            }
        }
        out
    }

    /// Доставка письма в ящик. Возвращает uid.
    pub fn deliver(&self, email: &str, data: &[u8], folder: &str) -> std::io::Result<u64> {
        let base = self.ensure_user(email)?;
        let fdir = folder_dir(&base, folder);
        for sub in ["tmp", "new", "cur"] {
            std::fs::create_dir_all(fdir.join(sub))?;
        }
        let (uv, mut un) = Self::read_meta(&fdir);
        let uid = un;
        un += 1;
        let t = now();
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let name = format!("{uid}.M{t}S{nano:09}.zent");
        let tmp_path = fdir.join("tmp").join(&name);
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        // доставляем сразу в cur (письмо без флагов = непрочитанное)
        std::fs::rename(&tmp_path, fdir.join("cur").join(&name))?;
        Self::write_meta(&fdir, uv, un)?;
        Ok(uid)
    }

    fn parse_msg(dir: &Path, name: &str) -> Option<MsgMeta> {
        let base = name.split('.').next()?.parse::<u64>().ok()?;
        let flags = name
            .rsplit_once(":2,")
            .map(|(_, f)| f.trim_end_matches(',').to_string())
            .unwrap_or_default();
        let md = std::fs::metadata(dir.join(name)).ok()?;
        Some(MsgMeta {
            uid: base,
            name: name.to_string(),
            flags,
            size: md.len(),
            mtime: md
                .modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    pub fn list(&self, email: &str, folder: &str) -> std::io::Result<Vec<MsgMeta>> {
        let fdir = folder_dir(&self.user_dir(email), folder);
        let mut out = Vec::new();
        for sub in ["new", "cur"] {
            if let Ok(entries) = std::fs::read_dir(fdir.join(sub)) {
                for e in entries.flatten() {
                    if let Some(m) = Self::parse_msg(&fdir.join(sub), &e.file_name().to_string_lossy())
                    {
                        out.push(m);
                    }
                }
            }
        }
        out.sort_by_key(|m| m.uid);
        Ok(out)
    }

    pub fn read(&self, email: &str, folder: &str, m: &MsgMeta) -> std::io::Result<Vec<u8>> {
        let fdir = folder_dir(&self.user_dir(email), folder);
        std::fs::read(fdir.join("cur").join(&m.name))
    }

    /// Установить флаги; возвращает новое имя файла.
    pub fn set_flags(
        &self,
        email: &str,
        folder: &str,
        m: &MsgMeta,
        flags: &str,
    ) -> std::io::Result<String> {
        let fdir = folder_dir(&self.user_dir(email), folder);
        let mut canon: String = flags.chars().filter(|c| "DFPRST".contains(*c)).collect();
        canon = {
            let mut v: Vec<char> = canon.chars().collect();
            v.sort();
            v.dedup();
            v.into_iter().collect()
        };
        let base = m.name.split(":2,").next().unwrap_or(&m.name);
        let new_name = if canon.is_empty() {
            base.to_string()
        } else {
            format!("{base}:2,{canon}")
        };
        let from = fdir.join("cur").join(&m.name);
        let to = fdir.join("cur").join(&new_name);
        if from != to {
            std::fs::rename(from, to)?;
        }
        Ok(new_name)
    }

    pub fn delete_msg(&self, email: &str, folder: &str, m: &MsgMeta) -> std::io::Result<()> {
        let fdir = folder_dir(&self.user_dir(email), folder);
        for sub in ["cur", "new"] {
            let p = fdir.join(sub).join(&m.name);
            if p.exists() {
                std::fs::remove_file(p)?;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Список всех писем юзера по всем папкам (для репликации/статистики).
    pub fn user_stats(&self, email: &str) -> (u64, u64) {
        let mut msgs = 0u64;
        let mut bytes = 0u64;
        for f in self.list_folders(email) {
            if let Ok(list) = self.list(email, &f) {
                msgs += list.len() as u64;
                bytes += list.iter().map(|m| m.size).sum::<u64>();
            }
        }
        (msgs, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64_decode;

    #[test]
    fn maildir_lifecycle() {
        let tmp = std::env::temp_dir().join(format!("zent-test-{}", crate::util::urandom(4).iter().map(|b| format!("{b:02x}")).collect::<String>()));
        let st = Store::new(&tmp);
        let uid = st.deliver("alice@rival-afk.com", b"Subject: t\r\n\r\nhi\r\n", "").unwrap();
        assert_eq!(uid, 1);
        let uid2 = st.deliver("alice@rival-afk.com", b"Subject: t2\r\n\r\nhi\r\n", "").unwrap();
        assert_eq!(uid2, 2);
        let list = st.list("alice@rival-afk.com", "").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].flags, "");
        let nn = st.set_flags("alice@rival-afk.com", "", &list[1], "SR").unwrap();
        assert!(nn.ends_with(":2,RS"));
        let list = st.list("alice@rival-afk.com", "").unwrap();
        assert_eq!(list[1].flags, "RS");
        let data = st.read("alice@rival-afk.com", "", &list[0]).unwrap();
        assert!(data.starts_with(b"Subject: t"));
        st.create_folder("alice@rival-afk.com", "Archive").unwrap();
        assert!(st.list_folders("alice@rival-afk.com").contains(&"Archive".to_string()));
        st.deliver("alice@rival-afk.com", b"x", "Archive").unwrap();
        assert_eq!(st.list("alice@rival-afk.com", "Archive").unwrap().len(), 1);
        st.delete_msg("alice@rival-afk.com", "", &list[0]).unwrap();
        assert_eq!(st.list("alice@rival-afk.com", "").unwrap().len(), 1);
        st.remove_user("alice@rival-afk.com").unwrap();
        let _ = b64_decode("");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
