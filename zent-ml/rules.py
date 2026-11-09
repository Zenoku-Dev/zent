# -*- coding: utf-8 -*-
"""Правила-дополнения к нейронке (как ad_rules.py у bbot).

score_rules возвращает добавку к logit: явный спам/фишинг форсируется вверх,
личная переписка с вопросом и без ссылок — чуть вниз. Модель всё равно решает.
"""
import re

_FORCE_SPAM = [
    re.compile(r"(viagra|v1agra|cialis|casino|казино|1xbet|vulkan)\S*", re.I),
    re.compile(r"вы?игр\w* в (лотар|лотере|розыгрыш)|you won|lottery winner|claim (your )?prize", re.I),
    re.compile(r"(подтверд\w* (аккаунт|личн\w* данные|пароль))|verify your account.{0,40}(click|перейд)", re.I),
    re.compile(r"аккаунт (был )?(заблок|приостанов)", re.I),
    re.compile(r"https?://\S+\.(ru|top|xyz|click|online)/\S*(bonus|casino|win|gift)", re.I),
    re.compile(r"(заработ\w* (от|более)? ?\d+.{0,6}(руб|\$|usd)|пассивный доход)", re.I),
    re.compile(r"(снижение веса|похудеть за|slimming|weight.?loss).{0,20}(капсул|таблетк|pill)", re.I),
    re.compile(r"kein metamask|seed.?phrase.{0,30}(введите|enter|отправ)", re.I),
]

_SOFT_HAM = re.compile(
    r"^(re|fwd):\s", re.I
)


def score_rules(text: str) -> float:
    t = (text or "")[:4000]
    low = t.lower()
    add = 0.0
    for rx in _FORCE_SPAM:
        if rx.search(low):
            add += 4.0
    if _SOFT_HAM.search(t):
        add -= 1.0
    # короткое личное сообщение с вопросом — не похоже на спам
    words = low.split()
    if len(words) <= 30 and "?" in t and "http" not in low:
        add -= 0.7
    return add
