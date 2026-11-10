#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Обучение spam-модели zent (bbot-совместимый формат spam_model.bin).

Источники:
  SpamAssassin Public Corpus (tars из data/)  — ham/spam, en
  hf_anti_spam_ru.csv                          — text,is_spam (ru, 0/1)
  hf_telegram_spam_ham.csv                     — text_type(spam/ham),text (en)

Таргет: BCEWithLogits(pos_weight). Модель: EmbBag(mean) -> MLP + Wide(mean).
Формат сохранения: <i32 len><json header><f32: emb,w1,b1,w2,b2,wide> — как в bbot.
"""
import csv
import json
import math
import os
import random
import struct
import sys
import tarfile
import io
from email import policy
from email.parser import BytesParser
from email.header import decode_header

import numpy as np
import torch
import torch.nn as nn

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from features import features_unique, BUCKETS  # noqa

DIM = 16
HIDDEN = 32
THRESHOLD = 0.65
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

SA_HAM = ["20021010_easy_ham.tar.bz2", "20021010_hard_ham.tar.bz2", "20030228_easy_ham_2.tar.bz2"]
SA_SPAM = ["20030228_spam.tar.bz2", "20030228_spam_2.tar.bz2"]


def sa_texts(name):
    path = os.path.join(HERE, "data", name)
    out = []
    with tarfile.open(path, "r:bz2") as t:
        for m in t:
            if not m.isfile():
                continue
            try:
                raw = t.extractfile(m).read()
                msg = BytesParser(policy=policy.default).parsebytes(raw)
                subj = msg.get("Subject", "")
                try:
                    subj = str(decode_header(subj)[0][0])
                    if isinstance(subj, bytes):
                        subj = subj.decode("utf-8", "ignore")
                except Exception:
                    subj = str(subj)
                body = ""
                if msg.is_multipart():
                    for p in msg.walk():
                        if p.get_content_type() == "text/plain":
                            try:
                                body += p.get_content() or ""
                            except Exception:
                                pass
                            break
                else:
                    try:
                        body = msg.get_content() or ""
                    except Exception:
                        body = raw.decode("utf-8", "ignore")
                txt = (subj + "\n" + body).strip()
                if len(txt) >= 30:
                    out.append(txt)
            except Exception:
                continue
    return out


def csv_texts(path, text_key, label_key, spam_values, limit_ham, limit_spam):
    ham, spam = [], []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            t = (row.get(text_key) or "").strip()
            if len(t) < 20:
                continue
            lab = (row.get(label_key) or "").strip().lower()
            if lab in spam_values:
                if len(spam) < limit_spam:
                    spam.append(t)
            else:
                if len(ham) < limit_ham:
                    ham.append(t)
    return ham, spam


def load():
    docs = []  # (text, y)
    for f in SA_HAM:
        for t in sa_texts(f):
            docs.append((t, 0))
    for f in SA_SPAM:
        for t in sa_texts(f):
            docs.append((t, 1))
    print("spamassassin: %d docs (ham %d / spam %d)" % (
        len(docs), sum(1 for _, y in docs if y == 0), sum(1 for _, y in docs if y == 1)), flush=True)

    p = os.path.join(HERE, "data", "hf_anti_spam_ru.csv")
    ham, spam = csv_texts(p, "text", "is_spam", {"1"}, 7000, 7000)
    print("ru_hf: ham %d spam %d" % (len(ham), len(spam)), flush=True)
    docs += [(t, 0) for t in ham] + [(t, 1) for t in spam]

    p = os.path.join(HERE, "data", "hf_telegram_spam_ham.csv")
    ham, spam = csv_texts(p, "text", "text_type", {"spam"}, 3000, 3000)
    print("telegram: ham %d spam %d" % (len(ham), len(spam)), flush=True)
    docs += [(t, 0) for t in ham] + [(t, 1) for t in spam]
    return docs


def encode(docs):
    enc = []
    for i, (text, y) in enumerate(docs):
        ids = features_unique(text[:6000], BUCKETS)
        ids = [i for i in ids if 0 <= i < BUCKETS]
        if len(ids) < 3:
            continue
        enc.append((ids, y))
        if len(enc) % 10000 == 0:
            print("encoded %d" % len(enc), flush=True)
    return enc


class Model(nn.Module):
    def __init__(self):
        super().__init__()
        self.emb = nn.EmbeddingBag(BUCKETS, DIM, mode="mean")
        self.fc1 = nn.Linear(DIM, HIDDEN)
        self.fc2 = nn.Linear(HIDDEN, 1)
        self.wide = nn.EmbeddingBag(BUCKETS, 1, mode="mean")

    def forward(self, flat_ids, offsets):
        v = self.emb(flat_ids, offsets)
        h = torch.relu(self.fc1(v))
        out = self.fc2(h).squeeze(1)
        out = out + self.wide(flat_ids, offsets).squeeze(1)
        return out


def val_metrics(model, data, bs=256):
    model.eval()
    order = sorted(range(len(data)), key=lambda i: len(data[i][0]))
    # батчи по одинаковой длине — EmbeddingBag принимает flat+offsets
    tp = fp = fn = tn = 0
    scores = []
    ys = []
    with torch.no_grad():
        i = 0
        while i < len(order):
            batch = order[i:i + bs]
            i += bs
            flat = []
            offsets = []
            for j in batch:
                offsets.append(len(flat))
                flat.extend(data[j][0])
            logits = model(torch.tensor(flat), torch.tensor(offsets))
            probs = torch.sigmoid(logits).tolist()
            scores.extend(probs)
            ys.extend(data[j][1] for j in batch)
    # считаем по вероятностям при фиксированном пороге
    for p, y in zip(scores, ys):
        pred = 1 if p >= THRESHOLD else 0
        if pred == y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 1:
            fn += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    acc = (tp + tn) / max(1, len(ys))
    # PR-AUC по сетке порогов
    auc = 0.0
    grid = [i / 100 for i in range(5, 100, 5)]
    prevs, recs = [], []
    for t in grid:
        tp2 = sum(1 for p, y in zip(scores, ys) if p >= t and y == 1)
        fp2 = sum(1 for p, y in zip(scores, ys) if p >= t and y == 0)
        fn2 = sum(1 for p, y in zip(scores, ys) if p < t and y == 1)
        prevs.append(tp2 / (tp2 + fp2) if tp2 + fp2 else 1.0)
        recs.append(tp2 / (tp2 + fn2) if tp2 + fn2 else 0.0)
    for k in range(1, len(grid)):
        auc += (recs[k - 1] - recs[k] if recs[k - 1] > recs[k] else recs[k] - recs[k - 1]) * (prevs[k - 1] + prevs[k]) / 2
    return acc, prec, rec, auc


def main():
    docs = load()
    random.shuffle(docs)
    enc = encode(docs)
    n = len(enc)
    nv = max(200, n // 10)
    train, val = enc[nv:], enc[:nv]
    print("train %d val %d" % (len(train), len(val)), flush=True)

    model = Model()
    opt = torch.optim.Adam(model.parameters(), lr=3e-4)
    pw = torch.tensor([1.4])
    lossf = nn.BCEWithLogitsLoss(pos_weight=pw)

    order = list(range(len(train)))
    for epoch in range(6):
        model.train()
        random.shuffle(order)
        tot = 0.0
        nb = 0
        i = 0
        while i < len(order):
            batch = order[i:i + 128]
            i += 128
            flat = []
            offsets = []
            labels = []
            for j in batch:
                offsets.append(len(flat))
                flat.extend(train[j][0])
                labels.append(train[j][1])
            logits = model(torch.tensor(flat), torch.tensor(offsets))
            loss = lossf(logits, torch.tensor(labels, dtype=torch.float32))
            opt.zero_grad()
            loss.backward()
            opt.step()
            tot += loss.item()
            nb += 1
        acc, prec, rec, auc = val_metrics(model, val)
        print("epoch %d loss %.4f | val acc %.3f prec %.3f rec %.3f pr-auc %.3f" % (
            epoch, tot / max(1, nb), acc, prec, rec, auc), flush=True)

    # ожидаемая по bbot раскладка
    state = model.state_dict()
    emb = state["emb.weight"].detach().cpu().numpy().astype("<f4")  # BUCKETS x DIM
    w1 = state["fc1.weight"].detach().cpu().numpy().astype("<f4")   # HIDDEN x DIM
    b1 = state["fc1.bias"].detach().cpu().numpy().astype("<f4")
    w2 = state["fc2.weight"].detach().cpu().numpy().astype("<f4")   # 1 x HIDDEN
    b2 = state["fc2.bias"].detach().cpu().numpy().astype("<f4")
    wide = state["wide.weight"].detach().cpu().numpy().astype("<f4").reshape(-1)  # BUCKETS

    header = {
        "buckets": BUCKETS,
        "dim": DIM,
        "hidden": HIDDEN,
        "threshold": THRESHOLD,
        "version": 2,
        "feature_version": 2,
        "wide": True,
    }
    payload = json.dumps(header, separators=(",", ":")).encode("utf-8")
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "spam_model.bin")
    with open(out_path, "wb") as f:
        f.write(struct.pack("<i", len(payload)))
        f.write(payload)
        f.write(emb.tobytes())   # (emb[bucket] for bucket in buckets) row-major
        f.write(w1.tobytes())    # HIDDEN*DIM row-major w1[hidden][dim]
        f.write(b1.tobytes())
        f.write(w2.reshape(-1).tobytes())
        f.write(b2.tobytes())
        f.write(wide.tobytes())
    print("saved %s (%d bytes)" % (out_path, os.path.getsize(out_path)), flush=True)


if __name__ == "__main__":
    main()
