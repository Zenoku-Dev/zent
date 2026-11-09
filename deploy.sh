#!/bin/sh
# deploy.sh — деплой zent на VPS через rsh (инструмент агента, сам zent rsh не использует)
# usage: ./deploy.sh [rsh-лейбл VPS, default: vps]
set -e
HOST="${1:-vps}"
RSH="${RSH:-rsh}"

echo "==> пушим исходники на $HOST"
$RSH "$HOST" exec "mkdir -p ~/src/zent/src ~/src/zent/zent-ml"
for f in Cargo.toml; do
  $RSH "$HOST" push "$f" "~/src/zent/$f"
done
for f in src/*.rs; do
  $RSH "$HOST" push "$f" "~/src/zent/$f"
done

echo "==> rust/cargo на таргете"
$RSH "$HOST" exec 'command -v cargo >/dev/null 2>&1 || { command -v rustup >/dev/null 2>&1 || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; }; . $HOME/.cargo/env 2>/dev/null || true; cargo --version'

echo "==> сборка (release, без LTO — на VPS мало RAM)"
$RSH "$HOST" exec '. $HOME/.cargo/env 2>/dev/null; cd ~/src/zent && cargo build --release 2>&1 | tail -5'

echo "==> установка"
$RSH "$HOST" exec 'install -m 755 ~/src/zent/target/release/zent /usr/local/bin/zent && mkdir -p /etc/zent /var/lib/zent/mail /var/lib/zent/queue && [ -f /etc/zent/zent.conf ] || cp ~/src/zent/zent.conf.example /etc/zent/zent.conf'

echo "==> systemd"
$RSH "$HOST" push zent.service /etc/systemd/system/zent.service
$RSH "$HOST" exec 'systemctl daemon-reload && systemctl enable --now zent && systemctl status zent --no-pager | head -5'

echo "==> готово: zent на $HOST"
echo "    юзеры: zent user add alice@rival-afk.com"
echo "    TXT-записи: zent dns-records --ip 46.183.21.121"
