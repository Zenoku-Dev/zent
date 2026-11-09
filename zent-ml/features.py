# -*- coding: utf-8 -*-
"""Feature hashing для zent-ml (антиспам почты).

Порт features.py из bbot: та же схема — хэш FNV-1a в BUCKETS корзин,
мета-токены, семантические маркеры, символьные n-граммы. Токенизация одна
и та же для обучения (torch) и инференса (чистый python, spam_model.py).

Отличия от bbot-версии: семантика заточена под почтовый спам
(unsubscribe, verify/phishing, lottery, pharma, urgent).
"""
import re

BUCKETS = 32768
FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193
FEATURE_VERSION = 2

_url_re = re.compile(r"https?://\S+|www\.\S+|t\.me/\S+", re.IGNORECASE)
_mention_re = re.compile(r"@[a-zA-Z0-9_]{3,}")
_phone_re = re.compile(r"\+?\d[\d\s\-()]{8,}\d")
_price_re = re.compile(r"(?:\d+[\s.,]?\d*)\s*(?:₽|руб|рублей|р\.|\$|usd|eur|€)", re.IGNORECASE)
_punct_re = re.compile(r"[^\w\s?@]+", re.UNICODE)
_space_re = re.compile(r"\s+")

_ADULT_RE = re.compile(
    r"(порн|(?<![a-z])porn|(?<![a-z])xxx|(?<![a-z])s3x|(?<![a-z])sex|"
    r"onlyfans|интим|эскорт|18\+)",
    re.IGNORECASE,
)
_CHEAT_RE = re.compile(r"(чит|cheat|aimbot|hack|взлом)", re.IGNORECASE)
_CRYPTO_RE = re.compile(
    r"(?<![a-z])(?:btc|usdt|ton|eth|sol)(?![a-z])|крипт|биткоин|эфир|"
    r"инвест|пассивн\w* доход|заработ\w*",
    re.IGNORECASE,
)
_CASINO_RE = re.compile(r"(казино|ставк|букмекер|1xbet|vulkan|mostbet|joycasino|pin-up)", re.IGNORECASE)
_CHANNEL_RE = re.compile(r"(канал|тгк|telegram|телеграм|подпиш|подписк)", re.IGNORECASE)
_JOB_RE = re.compile(r"(работа|вакан|подработ|зарплат|набор в команду|ищу исполнител|удалённ)", re.IGNORECASE)
_GIVEAWAY_RE = re.compile(r"(розыгрыш|giveaway|подарок|промокод|бонус|скидк)", re.IGNORECASE)
_OFFER_RE = re.compile(
    r"(прода|куплю|заказ|услуг|регистрац|заработ|доход|инвест|бонус|"
    r"промокод|скидк|бесплатн|дешев|недорог|в лс|в личку)",
    re.IGNORECASE,
)
_CTA_RE = re.compile(
    r"(заход|перейд|жми|скач|смотр|подпиш|вступ|забир|получ|регистр|"
    r"click|install|download|watch|buy|order)",
    re.IGNORECASE,
)
_DM_RE = re.compile(r"(в\s+лс|в\s+личк|пиши|напиши|личные сообщения|dm\b)", re.IGNORECASE)
_SELF_RE = re.compile(
    r"(?<![а-яa-z])(?:я|мне|меня|мой|сделал|сделала|написал|написала)(?![а-яa-z])",
    re.IGNORECASE,
)
_TECH_RE = re.compile(r"(обнов|верси|установ|ошибк|файл|apk|не работает|баг|фикс)", re.IGNORECASE)
_NEG_RE = re.compile(r"(?<![а-яa-z])(?:не|нет|нельзя|без)(?![а-яa-z])", re.IGNORECASE)
_FREE_RE = re.compile(r"(бесплат|(?<![a-z])free(?![a-z]))", re.IGNORECASE)
_AD_TOPIC_RE = re.compile(
    r"(казино|ставк|крипт|чит|порн|интим|18\+|заработ|инвест|промокод|"
    r"розыгрыш|вакан|услуг|аккаунт|подписк|vpn|proxy|прокси)",
    re.IGNORECASE,
)
# --- почтовая специфика ---
_UNSUB_RE = re.compile(r"(отписа|unsubscribe|unsubscrib|opt.?out|не желаете получать)", re.IGNORECASE)
_VERIFY_RE = re.compile(
    r"(verify|verif|подтверд|восстанов|account.{0,15}(suspend|locked|disabled)|"
    r"аккаунт.{0,15}(заблок|приостанов)|password|логин|срок действия.{0,20}истек)",
    re.IGNORECASE,
)
_LOTTERY_RE = re.compile(
    r"(выиграл|выигрыш|winner|won\b|lottery|лотар|лотере|наследств|наслеdstv|"
    r"поздравля.{0,20}выбран|нашл.{0,10}кошел|claim your prize)",
    re.IGNORECASE,
)
_PHARMA_RE = re.compile(r"(viagra|v1agra|cialis|casino pills|аптек|лекарств|похуде|slimming)", re.IGNORECASE)
_URGENT_RE = re.compile(r"(срочн|немедлен|act now|limited time|last chance|final notice|48 hours|24 часа)", re.IGNORECASE)
_SHORT_RE = re.compile(r"(bit\.ly|tinyurl|goo\.gl|t\.co/|is\.gd|cutt\.ly|shorturl)", re.IGNORECASE)
_FWD_RE = re.compile(r"(fwd:|fw:|re:|пересыл)", re.IGNORECASE)


def normalize(text: str) -> str:
    text = (text or "").lower().replace("ё", "е").replace("’", "'").replace("`", "'")
    text = _url_re.sub(" link ", text)
    text = _mention_re.sub(" mention ", text)
    text = _phone_re.sub(" phone ", text)
    text = _price_re.sub(" price ", text)
    text = _punct_re.sub(" ", text)
    return _space_re.sub(" ", text).strip()


def _fnv(text: str, buckets: int) -> int:
    h = FNV_OFFSET
    for b in text.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h % buckets


def features(text: str, buckets: int = BUCKETS):
    raw = text or ""
    norm = normalize(raw)
    if not norm:
        norm = "?"
    padded = f" {norm} "
    words = norm.split()
    ids = []

    def mark(name):
        ids.append(_fnv("m:" + name, buckets))

    def cross(name):
        ids.append(_fnv("x:" + name, buckets))

    has_url = " link " in padded
    has_mention = " mention " in padded
    has_phone = " phone " in padded
    has_price = " price " in padded
    has_question = "?" in norm

    adult = bool(_ADULT_RE.search(norm))
    cheat = bool(_CHEAT_RE.search(norm))
    crypto = bool(_CRYPTO_RE.search(norm))
    casino = bool(_CASINO_RE.search(norm))
    channel = bool(_CHANNEL_RE.search(norm))
    job = bool(_JOB_RE.search(norm))
    giveaway = bool(_GIVEAWAY_RE.search(norm))
    offer = bool(_OFFER_RE.search(norm))
    cta = bool(_CTA_RE.search(norm))
    dm = bool(_DM_RE.search(norm))
    selfpromo = bool(_SELF_RE.search(norm))
    tech = bool(_TECH_RE.search(norm))
    neg = bool(_NEG_RE.search(norm))
    free = bool(_FREE_RE.search(norm))
    ad_topic = bool(_AD_TOPIC_RE.search(norm))
    # почтовые маркеры
    unsub = bool(_UNSUB_RE.search(norm))
    verify = bool(_VERIFY_RE.search(norm))
    lottery = bool(_LOTTERY_RE.search(norm))
    pharma = bool(_PHARMA_RE.search(norm))
    urgent = bool(_URGENT_RE.search(norm))
    shortlink = bool(_SHORT_RE.search(norm))
    fwd = bool(_FWD_RE.search(norm))

    ids.append(_fnv("wc:%d" % min(len(words), 20), buckets))
    ids.append(_fnv("q:%d" % (1 if has_question else 0), buckets))
    ids.append(_fnv("url:%d" % (1 if has_url else 0), buckets))
    ids.append(_fnv("mention:%d" % (1 if has_mention else 0), buckets))
    ids.append(_fnv("price:%d" % (1 if has_price else 0), buckets))
    ids.append(_fnv("phone:%d" % (1 if has_phone else 0), buckets))
    ids.append(_fnv("excl:%d" % (1 if "!" in raw else 0), buckets))
    ids.append(_fnv("nl:%d" % min(raw.count("\n"), 3), buckets))
    ids.append(_fnv("digits:%d" % (1 if any(ch.isdigit() for ch in raw) else 0), buckets))
    ids.append(_fnv("len:%d" % (0 if len(words) <= 3 else 1 if len(words) <= 10 else 2), buckets))
    ids.append(_fnv("urls:%d" % min(raw.lower().count("http") + raw.lower().count("t.me/"), 3), buckets))
    ids.append(_fnv("allcaps:%d" % (1 if raw and raw.isupper() else 0), buckets))

    for name, present in (
        ("adult", adult), ("cheat", cheat), ("crypto", crypto),
        ("casino", casino), ("channel", channel), ("job", job),
        ("giveaway", giveaway), ("offer", offer), ("cta", cta),
        ("dm", dm), ("self", selfpromo), ("tech", tech),
        ("neg", neg), ("free", free), ("adtopic", ad_topic),
        ("unsub", unsub), ("verify", verify), ("lottery", lottery),
        ("pharma", pharma), ("urgent", urgent), ("short", shortlink),
        ("fwd", fwd),
    ):
        if present:
            mark(name)

    for a, b in (
        ("url", "cta"), ("url", "offer"), ("url", "free"),
        ("url", "adult"), ("url", "channel"), ("url", "casino"),
        ("url", "crypto"), ("url", "cheat"), ("url", "verify"),
        ("url", "lottery"), ("url", "pharma"), ("url", "urgent"),
        ("url", "short"), ("url", "unsub"),
        ("verify", "cta"), ("verify", "urgent"), ("verify", "urgent"),
        ("lottery", "cta"), ("lottery", "free"), ("lottery", "price"),
        ("pharma", "free"), ("pharma", "cta"),
        ("unsub", "offer"), ("unsub", "cta"), ("unsub", "channel"),
        ("urgent", "offer"), ("urgent", "free"),
        ("crypto", "cta"), ("crypto", "offer"),
        ("channel", "cta"), ("channel", "free"),
        ("giveaway", "cta"), ("job", "dm"), ("job", "offer"),
        ("dm", "offer"), ("dm", "cta"),
        ("price", "offer"), ("price", "dm"),
        ("adult", "cta"), ("adult", "url"),
        ("neg", "offer"), ("free", "offer"), ("free", "cta"),
    ):
        pass  # разворачивается ниже по наличию

    def cross_pair(a, b):
        if a and b:
            ids.append(0)  # placeholder, заменяется ниже

    # честные кроссы (по булевым флагам)
    for name, flag in (("has_url", has_url),):
        _ = name, flag
    if has_url and cta: cross("url_cta")
    if has_url and offer: cross("url_offer")
    if has_url and selfpromo: cross("url_self")
    if has_url and free: cross("url_free")
    if has_url and adult: cross("url_adult")
    if has_url and channel: cross("url_channel")
    if has_url and tech: cross("url_tech")
    if has_url and casino: cross("url_casino")
    if has_url and crypto: cross("url_crypto")
    if has_url and cheat: cross("url_cheat")
    if has_url and verify: cross("url_verify")
    if has_url and lottery: cross("url_lottery")
    if has_url and pharma: cross("url_pharma")
    if has_url and urgent: cross("url_urgent")
    if has_url and shortlink: cross("url_short")
    if has_url and unsub: cross("url_unsub")
    if has_mention and offer: cross("mention_offer")
    if has_mention and channel: cross("mention_channel")
    if has_price and offer: cross("price_offer")
    if has_price and dm: cross("price_dm")
    if has_price and lottery: cross("price_lottery")
    if dm and offer: cross("dm_offer")
    if dm and cta: cross("dm_cta")
    if channel and cta: cross("channel_cta")
    if channel and free: cross("channel_free")
    if tech and unsub: cross("tech_unsub")
    if selfpromo and cta: cross("self_cta")
    if selfpromo and has_url: cross("self_url")
    if adult and cta: cross("adult_cta")
    if adult and has_url: cross("adult_url")
    if neg and offer: cross("neg_offer")
    if verify and cta: cross("verify_cta")
    if verify and urgent: cross("verify_urgent")
    if lottery and cta: cross("lottery_cta")
    if lottery and free: cross("lottery_free")
    if pharma and free: cross("pharma_free")
    if urgent and offer: cross("urgent_offer")
    if unsub and offer: cross("unsub_offer")
    if unsub and channel: cross("unsub_channel")
    if crypto and cta: cross("crypto_cta")

    if words:
        ids.append(_fnv("f:" + words[0], buckets))
        ids.append(_fnv("l:" + words[-1], buckets))

    for w in words:
        ids.append(_fnv("w:" + w, buckets))

    for i in range(len(words) - 2):
        ids.append(_fnv("t:" + words[i] + "_" + words[i + 1] + "_" + words[i + 2], buckets))

    for i in range(len(words) - 1):
        ids.append(_fnv("b:" + words[i] + "_" + words[i + 1], buckets))

    for w in words:
        padded_word = "#" + w + "$"
        n = len(padded_word)
        for size in (3, 4, 5):
            for i in range(n - size + 1):
                ids.append(_fnv("c%d:%s" % (size, padded_word[i:i + size]), buckets))

    return ids


def features_unique(text: str, buckets: int = BUCKETS):
    return list(dict.fromkeys(features(text, buckets)))
