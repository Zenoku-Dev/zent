<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Zenoku-Dev/zenoku-design/main/assets/zent/readme-banner-animated-dark.svg">
    <img src="https://raw.githubusercontent.com/Zenoku-Dev/zenoku-design/main/assets/zent/readme-banner-animated.svg" alt="zent" width="440">
  </picture>
</p>

# Zent — Zenoku Post

Полностью свой почтовый сервис на Rust: SMTP, POP3, IMAP, свой DNS-резолвер,
свой DKIM/SPF/DMARC, свой Maildir — **без postfix/dovecot и вообще без
почтовых зависимостей** (только tokio + rustls). Антиспам — нейронка как в
`~/projects/stos/bbot` (hashed char/word n-gram embedding-bag + wide MLP),
живёт на redmi, VPS дергает её по своему агент-протоколу.

## Архитектура

```
                    ┌──────────────── VPS (46.183.21.121) ───────────────┐
 другие MX ──:25──► │ zent: SMTP 25/587/465, POP3 110/995, IMAP 143/993  │
                    │  Maildir /var/lib/zent/mail                        │
                    │  спул исходящих (MX-доставка или smarthost)        │
                    └──────────────▲─────────────────────────────────────┘
                                   │ TCP 7666, токен; телефон сам dialит
                    ┌──────────────┴──────────── redmi ──────────────────┐
                    │ zent-ml/agent.py                                   │
                    │  • спам-скоринг (spam_model.bin, pure python)      │
                    │  • копия Maildir ~/zent-mail (SYNC/RESTORE)        │
                    └────────────────────────────────────────────────────┘
```

- **SMTP in** (25): приём для `domains`, SPF-проверка + `Received-SPF`,
  DKIM-verify + `Authentication-Results`, DMARC `p=reject` отбрасывает
  непрошедшее. Спам (score ≥ `ml_threshold`) уходит в папку `Junk`.
- **SMTP submission** (587/465): AUTH PLAIN/LOGIN, релей на чужие домены,
  исходящие подписываются DKIM (ed25519-sha256).
- **Очередь**: спул `queue/*.meta|.eml`, retry с backoff, bounce постмастера
  после 96 попыток. Прямая доставка по MX либо smarthost (`relay_host`).
- **IMAP/POP3**: Maildir-бэкенд, папки Maildir++ (`.Junk`, `.Archive`...),
  UIDL/UID валидность стабильные.
- **Агент-канал** (`agent_addr`, TCP 7666): redmi подключается сам (NAT не
  мешает), токен в `agent_token`. Команды: `SCORE` (нейронка), `SYNC`
  (Maildir юзера tar-потоком на телефон), `RESTORE` (восстановление стора,
  если на VPS пусто). zent **никак не использует rsh** — rsh только для
  деплоя человеком/агентом.
- **Репликация**: после каждой доставки/удаления юзер помечается dirty,
  фоновый таск досылает tar на телефон; полный экземпляр почты живёт на redmi.

## Сборка и деплой

```sh
# VPS (Debian 13, x86_64, 929MB RAM — сборка без LTO)
./deploy.sh vps

# антиспам-агент на redmi (Torch для инференса не нужен)
./ml-deploy.sh phone vps
```

## Антиспам-политика (для заявки провайдеру на открытие 25)

SPF/DKIM/DMARC/PTR настраиваются так:

```sh
zent dns-records --ip 46.183.21.121   # печатает TXT-записи для зоны
```

- SPF: `v=spf1 mx ip4:46.183.21.121 -all` (входящие проверяются тоже).
- DKIM: `zent._domainkey TXT v=DKIM1; k=ed25519; p=...` (ключ в
  `db/dkim/<domain>.pkcs8`, создаётся автоматически).
- DMARC: `v=DMARC1; p=quarantine; ...`.
- PTR (rDNS): `mail.rival-afk.com` → прописывается у хостера.

Массовые рассылки zent не шлёт; релей открыт только после AUTH.

## Аутентификация

Пароли zent **не хранит**: логин/пароль почты проверяются в общей системе
аутентификации (`auth.rival-afk.com`, `POST /v1/web/passlogin` — тот же
аккаунт, что у rsh/console). Ответ кэшируется на 5 минут, при недоступности
auth-сервера — откат на локальный hash (если задан через `zent user add
--pass`). После первого успешного логина ящик создаётся автоматически.
`auth_mode = local` отключает общую систему.

## CLI

```
zent run [config]            # сервер
zent user add <email> [--name N] [--pass P] | passwd | rm | list
zent dns-records [config] [--ip A.B.C.D]
zent queue list | flush
```

## Конфиг

Пример — `zent.conf.example` → `/etc/zent/zent.conf`. Пустой `addr` = слушатель
выключен. `agent_token` должен совпадать с `~/zent-ml/agent.json` на redmi.

## Статус

- [x] SMTP in/out, submission, очередь, bounce
- [x] SPF, DKIM (ed25519), DMARC, `zent dns-records`
- [x] POP3, IMAP (subset: FETCH/SEARCH/STORE/APPEND/IDLE/...)
- [x] Maildir + репликация на redmi, восстановление
- [x] Нейро-антиспам на телефоне (SpamAssassin corpus + ru-spam датасет)
- [ ] DANE/спам-пад рейтингов, веб-интерфейс
