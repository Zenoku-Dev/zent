#!/bin/sh
# deploy.sh — деплой zent на VPS.
#   1) x86_64-бинарь кладём на VPS (scp)
#   2) кладём zent.conf (если ещё нет — ставим из файла)
#   3) ставим systemd-сервис и запускаем
# usage: ./deploy.sh <бинарь> [zent.conf]
set -e
HOST="${HOST:-vps}"
VPS_IP="${VPS_IP:-46.183.21.121}"
VPS_KEY="${VPS_KEY:-$HOME/.ssh/zenoku-vps}"
RSH="${RSH:-$HOME/.local/bin/rsh}"
BIN="${1:-./zent}"
CONF="${2:-./build-out/zent.conf}"
REMOTE_BIN="/usr/local/bin/zent"

[ -f "$BIN" ] || { echo "нет бинаря $BIN — собери его"; exit 1; }
echo "==> бинарь: $BIN ($(sha256sum "$BIN" | cut -d' ' -f1 | head -c 16)…)"

echo "==> scp бинарь -> $VPS_IP:$REMOTE_BIN"
scp -i "$VPS_KEY" -o IdentitiesOnly=yes -o BatchMode=yes "$BIN" "root@$VPS_IP:$REMOTE_BIN"

echo "==> каталоги + конф (scp-им новый, если текущего нет)"
$RSH "$HOST" exec 'chmod 755 /usr/local/bin/zent && mkdir -p /etc/zent /var/lib/zent/mail /var/lib/zent/queue /var/lib/zent/db'
if $RSH "$HOST" exec 'test -f /etc/zent/zent.conf && echo exists' | grep -q exists; then
  echo "    /etc/zent/zent.conf уже есть — не трогаем"
else
  scp -i "$VPS_KEY" -o IdentitiesOnly=yes -o BatchMode=yes "$CONF" "root@$VPS_IP:/etc/zent/zent.conf"
fi

echo "==> systemd"
scp -i "$VPS_KEY" -o IdentitiesOnly=yes -o BatchMode=yes "$(dirname "$0")/zent.service" "root@$VPS_IP:/etc/systemd/system/zent.service"
$RSH "$HOST" exec 'systemctl daemon-reload && systemctl enable --now zent && systemctl status zent --no-pager | head -6'

echo "==> готово"
echo "    юзеры:    zent user add alice@rival-afk.com"
echo "    DNS TXT:  zent dns-records --ip $VPS_IP"
echo "    порты:    587 открыт, 25 ждёт провайдера (входящий MX)"
