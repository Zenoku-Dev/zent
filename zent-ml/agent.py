#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""zent-agent — телефонная часть Zent (redmi).

Сам дialит на VPS (agent_addr в zent.conf), авторизуется токеном и держит
соединение. VPS по нему:
  SCORE <n>\n<text>   -> "SCORE <p>\n"  — спам-скоринг нейронкой (как bbot)
  SYNC <user> <n>\n<tar> -> "SYNC OK|ERR\n" — Maildir юзера на телефон
  RESTORE\n           -> "RESTORE <n>\n<tar>" — копия стора с телефона
  PING\n              -> (без ответа, keepalive)

Запуск (Termux): python3 ~/zent-ml/agent.py [agent.json]
"""
import json
import os
import socket
import struct
import sys
import tarfile
import time
import io
import math

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from features import features_unique  # noqa: E402
from rules import score_rules  # noqa: E402


class SpamModel:
    """Pure-python инференс: hashed embedding-bag + wide skip + MLP.
    Формат spam_model.bin идентичен bbot/ml/ad_model.bin."""

    def __init__(self, path=None):
        path = path or os.path.join(HERE, "spam_model.bin")
        with open(path, "rb") as f:
            data = f.read()
        hlen = struct.unpack_from("<i", data, 0)[0]
        self.meta = json.loads(data[4:4 + hlen].decode("utf-8"))
        self.buckets = self.meta["buckets"]
        self.dim = self.meta["dim"]
        self.hidden = self.meta["hidden"]
        self.threshold = float(self.meta.get("threshold", 0.65))
        pos = 4 + hlen
        size = lambda n: n * 4  # noqa: E731

        def take(n):
            nonlocal pos
            a = array_f(data[pos:pos + size(n)])
            pos += size(n)
            return a

        self.emb = take(self.buckets * self.dim)
        self.w1 = take(self.hidden * self.dim)
        self.b1 = take(self.hidden)
        self.w2 = take(self.hidden)
        self.b2 = take(1)[0]
        self.wide = take(self.buckets) if self.meta.get("wide") else None

    def proba(self, text: str) -> float:
        text = (text or "")[:6000]
        ids = features_unique(text, self.buckets)
        if not ids:
            return 0.0
        dim = self.dim
        emb = self.emb
        v = [0.0] * dim
        for i in ids:
            base = i * dim
            for d in range(dim):
                v[d] += emb[base + d]
        inv = 1.0 / len(ids)
        for d in range(dim):
            v[d] *= inv
        w1 = self.w1
        b1 = self.b1
        h = [0.0] * self.hidden
        for j in range(self.hidden):
            s = b1[j]
            base = j * dim
            for d in range(dim):
                s += w1[base + d] * v[d]
            h[j] = s if s > 0.0 else 0.0
        logit = self.b2
        for j in range(self.hidden):
            logit += self.w2[j] * h[j]
        if self.wide is not None:
            wide = self.wide
            total = 0.0
            for i in ids:
                total += wide[i]
            logit += total / len(ids)
        logit += score_rules(text)
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, logit))))


def array_f(raw):
    # little-endian float32 без array.array (struct.unpack быстрее чем cycle)
    n = len(raw) // 4
    return list(struct.unpack("<%df" % n, raw)) if n else []


def safe_name(user):
    return "".join(
        c if (c.isascii() and (c.isalnum() or c in "@._-")) else "_" for c in user.lower()
    )


class Agent:
    def __init__(self, cfg):
        self.host = cfg["host"]
        self.port = int(cfg.get("port", 7666))
        self.token = cfg["token"]
        self.dir = os.path.expanduser(cfg.get("dir", "~/zent-mail"))
        os.makedirs(self.dir, exist_ok=True)
        self.model = None
        try:
            self.model = SpamModel()
            print("model loaded: threshold %.2f, version %s" %
                  (self.model.threshold, self.model.meta.get("version")), flush=True)
        except FileNotFoundError:
            print("WARNING: spam_model.bin не найден — SCORE всегда 0.0", flush=True)

    def score(self, text):
        if self.model is None:
            return 0.0
        return round(self.model.proba(text), 4)

    def sync_user(self, user, tar_bytes):
        name = safe_name(user)
        dst = os.path.join(self.dir, name)
        tmp = os.path.join(self.dir, ".tmp-" + name)
        if os.path.exists(tmp):
            os.system("rm -rf %s" % tmp)
        os.makedirs(tmp, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as t:
            t.extractall(tmp)
        if os.path.exists(dst):
            os.system("rm -rf %s" % dst)
        os.rename(tmp, dst)
        # бэкап-папка по юзеру
        return True

    def restore_tar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name in sorted(os.listdir(self.dir)):
                if name.startswith(".tmp-"):
                    continue
                p = os.path.join(self.dir, name)
                if os.path.isdir(p):
                    t.add(p, arcname=name)
        return buf.getvalue()

    def handle(self, conn):
        f = conn.makefile("rb")

        def readline():
            line = f.readline()
            if not line:
                raise ConnectionError("closed")
            return line.decode("utf-8", "replace").strip()

        def readn(n):
            b = bytearray()
            while len(b) < n:
                chunk = f.read(min(65536, n - len(b)))
                if not chunk:
                    raise ConnectionError("closed mid-payload")
                b.extend(chunk)
            return bytes(b)

        while True:
            line = readline()
            if not line:
                continue
            if line == "PING":
                continue
            if line.startswith("SCORE "):
                n = int(line.split()[1])
                text = readn(n).decode("utf-8", "replace")
                conn.sendall(("SCORE %s\n" % self.score(text)).encode())
            elif line.startswith("SYNC "):
                _, user, n = line.split()
                tar = readn(int(n))
                try:
                    self.sync_user(user, tar)
                    conn.sendall(b"SYNC OK\n")
                    print("synced %s (%d bytes)" % (user, len(tar)), flush=True)
                except Exception as e:
                    print("sync error: %s" % e, flush=True)
                    conn.sendall(b"SYNC ERR\n")
            elif line == "RESTORE":
                tar = self.restore_tar()
                conn.sendall(("RESTORE %d\n" % len(tar)).encode())
                conn.sendall(tar)
                print("restore: sent %d bytes" % len(tar), flush=True)

    def run(self):
        while True:
            try:
                s = socket.create_connection((self.host, self.port), timeout=15)
                s.settimeout(None)
                s.sendall(("AGENT %s\n" % self.token).encode())
                resp = s.makefile("rb").readline().decode().strip()
                if resp != "AGENT OK":
                    print("auth failed: %r" % resp, flush=True)
                    s.close()
                    time.sleep(30)
                    continue
                print("connected to %s:%d" % (self.host, self.port), flush=True)
                self.handle(s)
            except Exception as e:
                print("connection lost: %s; reconnect in 10s" % e, flush=True)
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(10)


if __name__ == "__main__":
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "agent.json")
    with open(cfg_path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    Agent(cfg).run()
