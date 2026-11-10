# AGENTS.md — правила для агентов

## Git-identity (обязательно)

Коммиты в этом репозитории делаются **только от лица организации
[Zenoku-Dev](https://github.com/Zenoku-Dev)**, никогда не от лица пользователя:

```sh
git config user.name "Zenoku Dev"
git config user.email "bot@rival-afk.com"
```

Локальный конфиг репозитория уже выставлен так. Не менять его, не подменять
глобальным или личным author, не коммитить от `rival-afk` или личного email.

## Прочие правила

- Push — только в `https://github.com/Zenoku-Dev/<repo>`, ветка `main`.
- Бренд-ассеты — в [zenoku-design](https://github.com/Zenoku-Dev/zenoku-design)
  (генерируются скриптами, руками не правятся).
