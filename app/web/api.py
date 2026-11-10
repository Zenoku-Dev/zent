#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""zent-mail-api — минимальная веб-почта поверх zent.

Слушает 127.0.0.1:18002, за nginx/rival-auth.
IMAP4_SSL (:993) — чтение, SMTP_SSL (:465) — отправка.
Вход — через rival-auth (POST /v1/web/passlogin): 200/403 — ОК, 401 — неверно.
Сессии — в памяти процесса (TTL 12 ч), пароль нигде не хранится на диске.
"""
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import time
import imaplib
import smtplib
from email import message_from_bytes
from email.header import decode_header
from email.utils import formatdate
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTH_URL = os.environ.get("RIVAL_AUTH_URL", "https://auth.rival-afk.com")
IMAP_HOST, IMAP_PORT = "127.0.0.1", 993
SMTP_HOST, SMTP_PORT = "127.0.0.1", 465
USERS_DB = os.environ.get("ZENT_USERS_DB", "/var/lib/zent/db/users")
STATIC_DIR = os.environ.get("ZENT_MAIL_STATIC", "/var/www/mail")
SESSION_TTL = 12 * 3600

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

sessions = {}  # sid -> {"user","pass","name","ts"}

def sess_get(sid):
    s = sessions.get(sid)
    if not s:
        return None
    if time.time() - s["ts"] > SESSION_TTL:
        sessions.pop(sid, None)
        return None
    return s

def sess_put(user, password, name):
    sid = base64.urlsafe_b64encode(os.urandom(21)).decode().rstrip("=")
    sessions[sid] = {"user": user, "pass": password, "name": name, "ts": time.time()}
    return sid

# --- явно ничего не печатаем в answer-time (логи через eprintln) ---
def passlogin(username, password):
    import urllib.request, urllib.error
    body = json.dumps({"username": username, "password": password}).encode()
    rq = urllib.request.Request(
        AUTH_URL.rstrip("/") + "/v1/web/passlogin",
        data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(rq, timeout=10) as r:
            return {200: True, 403: True}.get(r.status, False), r.read().decode()
    except urllib.error.HTTPError as e:
        if e.code in (200, 403):
            return True, e.read().decode(errors="replace")
        return False, e.read().decode(errors="replace") if e.fp else ""
    except Exception:
        return None, "unreachable"

def mail_user_info(email):
    """существует ли почтовый ящик в /var/lib/zent/db/users"""
    try:
        with open(USERS_DB, encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 2 and p[0].lower() == email:
                    return True, (p[2] if len(p) > 2 else "")
        return False, ""
    except FileNotFoundError:
        return False, ""

def imap_conn(sess):
    c = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=CTX, timeout=15)
    c.login(sess["user"], sess["pass"])
    return c

def imap_folders(c):
    out = []
    typ, data = c.list()
    for raw in data or []:
        s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        # '(\\Noselect) "/" "Sent folder"' | '\HasNoChildren Sent'
        m = re.search(r'"([^"]+)"\s*$', s) or re.search(r'\s([A-Za-z0-9_.\-]+)\s*$', s)
        if m:
            f = m.group(1)
            if f and f != "NIL":
                out.append(f)
    return out or ["INBOX"]

def hdr_decode(v):
    try:
        parts = decode_header(str(v))
    except Exception:
        return str(v)
    out = []
    for p, enc in parts:
        if isinstance(p, bytes):
            try:
                out.append(p.decode(enc or "utf-8", errors="replace"))
            except (LookupError, ValueError):
                out.append(p.decode("utf-8", errors="replace"))
        else:
            out.append(p)
    return "".join(out)

_ENVELOPE = re.compile(r"""
    ^\s*(\d+)\s*\(\s*UID\s+(\d+)\s+FLAGS\s*\(([^)]*)\)\s*RFC822\.SIZE\s+(\d+)\s*$
""", re.X)

def fetch_list(c, folder, start=1, limit=30):
    c.select(folder, readonly=True)
    typ, data = c.search(None, "ALL")
    ids = data[0] and data[0].split() or []
    total = len(ids)
    ids = ids[-start-limit+1: -start+1 if start > 1 else None]  # newest first
    if not ids:
        return []
    seq = b",".join(ids).decode()
    typ, data = c.fetch(seq,
        "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])")
    raw_items = {}
    cur_seq = None
    cur_buf = b""
    for item in data:
        if isinstance(item, tuple) and len(item) == 2:
            part = item[0]
            if isinstance(part, bytes):
                m = re.match(rb"(\d+)\s", part)
                if m:
                    cur_seq = int(m.group(0).strip())
                    cur_buf = part + item[1]
                    raw_items[cur_seq] = cur_buf
        elif isinstance(item, bytes):
            # байтовая строка с маркером — случай UID FETCH, добавляем к буферу
            m = re.match(rb"(\d+)\s", item)
            if m:
                cur_seq = int(m.group(0).strip())
                cur_buf = item + (cur_buf[len(cur_buf):] if False else b"")
                raw_items[cur_seq] = item
    out = []
    for seq_b in ids:
        conn_seq = int(seq_b)
        item = raw_items.get(conn_seq, b"")
        uid_m = re.search(rb"UID\s+(\d+)", item)
        fl_m = re.search(rb"FLAGS\s*\(([^)]*)\)", item)
        sz_m = re.search(rb"RFC822\.SIZE\s+(\d+)", item)
        # заголовки после пустой строки
        try:
            head = item.split(b"\r\n\r\n", 1)[0]
        except Exception:
            head = item
        import email
        try:
            msg = email.message_from_bytes(head + b"\r\n\r\n")
            subject = hdr_decode(msg.get("Subject", ""))
            frm = hdr_decode(msg.get("From", ""))
            to = hdr_decode(msg.get("To", ""))
            date = hdr_decode(msg.get("Date", ""))
        except Exception:
            subject = frm = to = date = ""
        flags = fl_m.group(1).decode() if fl_m else ""
        unread = "\\Seen" not in flags
        out.append({
            "seq": conn_seq, "uid": int(uid_m.group(1)) if uid_m else 0,
            "flags": flags, "size": int(sz_m.group(1)) if sz_m else 0,
            "subject": subject or "(без темы)",
            "from": frm, "to": to, "date": date,
            "unread": unread,
        })
    out.reverse()  # новые — первыми в ленте? нет: оставляем новые первыми
    return out, total

def body_decode(p):
    raw = p.get_payload(decode=True) or b""
    cs = p.get_content_charset() or "utf-8"
    try:
        return raw.decode(cs, errors="replace")
    except (LookupError, ValueError):
        return raw.decode("utf-8", errors="replace")

def fetch_full(c, folder, uid):
    c.select(folder, readonly=True)
    typ, data = c.uid("fetch", str(uid), "(FLAGS RFC822)")
    raw = b""
    for item in data or []:
        if isinstance(item, tuple) and len(item) == 2:
            raw += item[1]
        elif isinstance(item, bytes):
            raw += item
    msg = message_from_bytes(raw)
    text = html = ""
    att = []
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_maintype() == "multipart":
                continue
            disp = p.get_content_disposition()
            if disp == "attachment":
                att.append({"name": hdr_decode(p.get_filename() or "attachment"),
                            "type": p.get_content_type(),
                            "size": len(p.get_payload(decode=True) or b"")})
            elif p.get_content_type() == "text/plain" and not text:
                text = body_decode(p)
            elif p.get_content_type() == "text/html" and not html:
                html = body_decode(p)
    else:
        text = body_decode(msg)
    return {"from": hdr_decode(msg.get("From", "")),
            "to": hdr_decode(msg.get("To", "")),
            "subject": hdr_decode(msg.get("Subject", "")),
            "date": hdr_decode(msg.get("Date", "")),
            "text": text, "html": html, "attachments": att}

def msg_send(sess, to, subject, body):
    s = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=CTX, timeout=15)
    try:
        s.login(sess["user"], sess["pass"])
        m = EmailMessage()
        m["From"] = sess["user"]
        m["To"] = to
        m["Subject"] = subject
        m["Date"] = formatdate()
        m.set_content(body)
        s.send_message(m)
    finally:
        s.quit()

def json_out(handler, code, obj):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)

def read_body(handler):
    try:
        n = int(handler.headers.get("Content-Length", "0") or 0)
    except ValueError:
        return None
    if n > 1 << 20:
        return None
    return handler.rfile.read(n)

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "zent-mail-api/1.0"

    def log_message(self, *a):
        sys.stderr.write("mail-api %s %s\n" % (self.address_string(), (a[0] % a[1:] if len(a) > 1 else a)))

    def _sess(self):
        h = self.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            return sess_get(h[7:].strip())
        return None

    def _route(self, method):
        path = self.path.split("?", 1)[0].rstrip("/")
        if method == "GET" and path in ("", "/"):
            return self._static("index.html")
        if method == "GET" and re.match(r"^/[\w.\-]+$", path):
            return self._static(path[1:])

        # <======== LOGIN (без сессии) ========>
        if method == "POST" and path == "/api/login":
            body = read_body(self)
            data = {}
            try:
                data = json.loads(body or b"{}")
            except Exception:
                return json_out(self, 400, {"error": "bad json"})
            u = str(data.get("user", "")).strip().lower()
            p = str(data.get("pass", ""))
            if not u or not p:
                return json_out(self, 400, {"error": "missing credentials"})
            if "@" not in u:
                u += "@rival-afk.com"
            local = u.split("@", 1)[0]
            ok, detail = passlogin(local, p)
            if ok is True:
                found, name = mail_user_info(u)
                if not found:
                    return json_out(self, 403, {"error": "mailbox not found"})
                sid = sess_put(u, p, name)
                return json_out(self, 200, {"token": sid, "user": u, "name": name})
            if ok is False:
                return json_out(self, 401, {"error": "wrong password"})
            return json_out(self, 503, {"error": "auth unavailable"})

        sess = self._sess()
        if sess is None:
            return json_out(self, 401, {"error": "unauthorized"})

        if method == "POST" and path == "/api/logout":
            h = self.headers.get("Authorization", "")[7:].strip()
            sessions.pop(h, None)
            return json_out(self, 200, {"ok": True})

        if method == "GET" and path == "/api/me":
            return json_out(self, 200, {"user": sess["user"], "name": sess["name"]})

        if method == "GET" and path == "/api/folders":
            try:
                c = imap_conn(sess)
                folders = imap_folders(c)
                c.logout()
                return json_out(self, 200, {"folders": folders})
            except Exception as e:
                return json_out(self, 502, {"error": "imap: %s" % e})

        if method == "GET" and path == "/api/messages":
            import urllib.parse as up
            q = up.parse_qs(up.urlparse(self.path).query)
            folder = q.get("folder", ["INBOX"])[0]
            try:
                start = int(q.get("start", ["1"])[0])
                limit = min(100, int(q.get("limit", ["30"])[0]))
            except ValueError:
                return json_out(self, 400, {"error": "bad start/limit"})
            try:
                c = imap_conn(sess)
                msgs, total = fetch_list(c, folder, start, limit)
                c.logout()
                return json_out(self, 200, {"messages": msgs, "total": total})
            except Exception as e:
                return json_out(self, 502, {"error": "imap: %s" % e})

        m = re.match(r"^/api/messages/([^/]+)/(\d+)$", path)
        if method == "GET" and m:
            folder, uid = m.groups()
            try:
                c = imap_conn(sess)
                msg = fetch_full(c, folder, uid)
                # помечаем прочитанным
                try:
                    c.select(folder)
                    c.uid("store", str(uid), "+FLAGS", "(\\Seen)")
                except Exception:
                    pass
                c.logout()
                return json_out(self, 200, {"message": msg})
            except Exception as e:
                return json_out(self, 502, {"error": "imap: %s" % e})

        m = re.match(r"^/api/messages/([^/]+)/(\d+)/(delete|move)$", path)
        if method == "POST" and m:
            folder, uid, action = m.groups()
            body = read_body(self)
            dest = json_out and None
            try:
                dest = json.loads(body or b"{}").get("dest", "Trash")
            except Exception:
                dest = "Trash"
            if action == "delete" and not dest:
                dest = "Trash"
            if action == "move" and not dest:
                dest = "Junk"
            try:
                c = imap_conn(sess)
                c.select(folder)
                typ, data = c.uid("move", str(uid), dest)
                c.logout()
                if typ == "NO":
                    return json_out(self, 502, {"error": "imap move failed"})
                return json_out(self, 200, {"ok": True})
            except Exception as e:
                return json_out(self, 502, {"error": "imap: %s" % e})

        if method == "POST" and path == "/api/send":
            body = read_body(self)
            try:
                data = json.loads(body or b"{}")
            except Exception:
                return json_out(self, 400, {"error": "bad json"})
            to = str(data.get("to", "")).strip()
            subject = str(data.get("subject", "")).strip()
            text = str(data.get("body", ""))
            if not to or not subject:
                return json_out(self, 400, {"error": "missing to/subject"})
            try:
                msg_send(sess, to, subject, text)
            except Exception as e:
                return json_out(self, 502, {"error": "smtp: %s" % e})
            return json_out(self, 200, {"ok": True})

        return json_out(self, 404, {"error": "not found"})

    def _static(self, fname):
        if not re.match(r"^[A-Za-z0-9_.\-]+$", fname):
            return json_out(self, 400, {"error": "bad filename"})
        path = os.path.join(STATIC_DIR, fname)
        try:
            with open(path, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            body = b"<h1>404</h1><p>zent-mail-api</p>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        ctype = (
            "text/html; charset=utf-8" if fname.endswith(".html") else
            "application/javascript" if fname.endswith(".js") else
            "text/css; charset=utf-8" if fname.endswith(".css") else
            "image/svg+xml" if fname.endswith(".svg") else
            "application/octet-stream"
        )
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if fname == "index.html" else "max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

def main():
    port = int(os.environ.get("ZENT_MAIL_PORT", "18002"))
    print("zent-mail-api listening on 127.0.0.1:%d" % port, flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()

if __name__ == "__main__":
    main()
