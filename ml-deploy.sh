#!/bin/sh
# ml-deploy.sh — ставит антиспам-агент на redmi через rsh (только для деплоя;
# сам агент связывается с VPS напрямую по TCP, без rsh)
# usage: ./ml-deploy.sh [rsh-лейбл телефона, default: phone] [rsh-лейбл VPS, default: vps]
set -e
PHONE="${1:-phone}"
VPS="${2:-vps}"
RSH="${RSH:-rsh}"

echo "==> python на redmi"
$RSH "$PHONE" exec 'command -v python3 || pkg install -y python'

echo "==> пушим zent-ml на $PHONE"
$RSH "$PHONE" exec 'mkdir -p ~/zent-ml'
for f in features.py rules.py agent.py spam_model.bin spam_meta.json; do
  [ -f "$f" ] && $RSH "$PHONE" push "$f" "~/zent-ml/$f"
done
mkdir -p .tmp-ml
for f in features.py rules.py agent.py spam_model.bin spam_meta.json; do
  [ -f "$f" ] && cp "$f" ".tmp-ml/$f"
done
$RSH "$PHONE" exec 'mkdir -p ~/zent-ml'

echo "==> agent.json"
TOKEN=$($RSH "$VPS" exec 'grep -E "^agent_token" /etc/zent/zent.conf | cut -d= -f2 | tr -d " "'" 2>/dev/null || echo CHANGE-ME)
HOSTIP=$($RSH "$VPS" exec 'hostname -I 2>/dev/null | awk "{print \$1}"' 2>/dev/null || echo "46.183.21.121")
cat > .tmp-ml/agent.json <<EOF
{"host": "$HOSTIP", "port": 7666, "token": "$TOKEN", "dir": "~/zent-mail"}
EOF
$RSH "$PHONE" push .tmp-ml/agent.json '~/zent-ml/agent.json'
rm -rf .tmp-ml

echo "==> termux-запуск (sv/runit) или вручную:"
cat <<EOF
  на redmi: python3 ~/zent-ml/agent.py
  автостарт (Termux:Boot): mkdir -p ~/.termux/boot && создай файл:
    #!/data/data/com.termux/files/usr/bin/sh
    termux-wake-lock; python3 ~/zent-ml/agent.py >> ~/zent-ml/agent.log 2>&1 &
EOF
