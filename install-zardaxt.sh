#!/usr/bin/env bash
#
# install-zardaxt.sh — установка zardaxt (passive TCP/IP fingerprinting) на Linux-сервер.
#
# Назначение: zardaxt пассивно слушает входящие TCP SYN-пакеты и определяет ОС клиента
# по особенностям TCP/IP-стека. Используется, чтобы проверить, как со стороны сервера
# выглядит TCP/IP-отпечаток браузерных сессий (и совпадает ли он с заявленным User-Agent).
#
# Поддержка ОС: Debian 11/12, Ubuntu 20.04 / 22.04 / 24.04 (менеджер пакетов apt).
# Запуск: только из-под root или через sudo.
#
# Переопределяемые переменные окружения:
#   ZARDAXT_DIR      каталог установки           (по умолчанию /opt/zardaxt)
#   ZARDAXT_PORT     порт HTTP API               (по умолчанию 80)
#   ZARDAXT_BIND     адрес привязки API          (по умолчанию ::  — dual-stack IPv4+IPv6)
#   ZARDAXT_API_KEY  ключ для выгрузки всей базы  (по умолчанию случайный)
#   ZARDAXT_IFACE    сетевой интерфейс захвата    (по умолчанию интерфейс default-маршрута)
#
# Пример:  sudo ZARDAXT_PORT=9000 ./install-zardaxt.sh
#
set -euo pipefail

# ---- параметры -------------------------------------------------------------
ZARDAXT_DIR="${ZARDAXT_DIR:-/opt/zardaxt}"
ZARDAXT_REPO="${ZARDAXT_REPO:-https://github.com/NikolaiT/zardaxt.git}"
ZARDAXT_PORT="${ZARDAXT_PORT:-80}"
ZARDAXT_BIND="${ZARDAXT_BIND:-::}"
ZARDAXT_API_KEY="${ZARDAXT_API_KEY:-$(openssl rand -hex 16)}"
ZARDAXT_IFACE="${ZARDAXT_IFACE:-$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
SERVICE_NAME="zardaxt"

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- предусловия -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Запускай из-под root или через sudo."
command -v apt-get >/dev/null 2>&1 || die "Скрипт рассчитан на Debian/Ubuntu (apt-get не найден)."
[ -n "$ZARDAXT_IFACE" ] || die "Не удалось определить сетевой интерфейс. Запусти с ZARDAXT_IFACE=<имя>, напр.: sudo ZARDAXT_IFACE=eth0 bash install-zardaxt.sh"

# ---- 1. системные пакеты ---------------------------------------------------
log "Устанавливаю системные зависимости..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  git build-essential pkg-config \
  python3 python3-pip python3-venv python3-dev \
  libpcap-dev \
  python3-dpkt python3-netifaces python3-requests \
  tcpdump

# ---- 2. исходники ----------------------------------------------------------
if [ -d "$ZARDAXT_DIR/.git" ]; then
  log "Репозиторий уже есть — обновляю ($ZARDAXT_DIR)..."
  git -C "$ZARDAXT_DIR" pull --ff-only
else
  log "Клонирую zardaxt в $ZARDAXT_DIR..."
  git clone "$ZARDAXT_REPO" "$ZARDAXT_DIR"
fi
mkdir -p "$ZARDAXT_DIR/log"

# ---- 3. venv + Python-зависимости ------------------------------------------
# venv с --system-site-packages, чтобы видеть apt-пакеты dpkt/netifaces/requests;
# pcapy-ng ставим из pip — он собирается из исходников против libpcap-dev.
log "Создаю venv и ставлю Python-зависимости..."
python3 -m venv --system-site-packages "$ZARDAXT_DIR/venv"
"$ZARDAXT_DIR/venv/bin/pip" install --upgrade pip
"$ZARDAXT_DIR/venv/bin/pip" install pcapy-ng

# ---- 4. конфиг zardaxt.json ------------------------------------------------
log "Пишу конфиг $ZARDAXT_DIR/zardaxt.json..."
cat > "$ZARDAXT_DIR/zardaxt.json" <<EOF
{
  "interface": "${ZARDAXT_IFACE}",
  "api_server_ip": "${ZARDAXT_BIND}",
  "api_server_port": ${ZARDAXT_PORT},
  "verbose": false,
  "api_key": "${ZARDAXT_API_KEY}",
  "pcap_filter": "tcp",
  "store_fingerprints": false,
  "write_after": 1000,
  "clear_dict_after": 5000
}
EOF

# ---- 5. systemd-сервис -----------------------------------------------------
log "Создаю systemd-юнит /etc/systemd/system/${SERVICE_NAME}.service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=zardaxt passive TCP/IP fingerprinting
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${ZARDAXT_DIR}
ExecStart=${ZARDAXT_DIR}/venv/bin/python ${ZARDAXT_DIR}/zardaxt.py ${ZARDAXT_DIR}/zardaxt.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true
systemctl enable --now "${SERVICE_NAME}.service"

# ---- 6. firewall (если ufw активен) ----------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  log "ufw активен — открываю порт ${ZARDAXT_PORT}/tcp..."
  ufw allow "${ZARDAXT_PORT}/tcp" >/dev/null || true
fi

# ---- 7. итог + проверка ----------------------------------------------------
sleep 2
PUB_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  log "Сервис ${SERVICE_NAME} запущен."
  log "Интерфейс захвата: ${ZARDAXT_IFACE}"
  log "API:       http://${PUB_IP:-<IP_сервера>}:${ZARDAXT_PORT}/classify"
  log "API key:   ${ZARDAXT_API_KEY}"
  log "Логи:      journalctl -u ${SERVICE_NAME} -f"
else
  warn "Сервис не активен. Последние строки лога:"
  journalctl -u "${SERVICE_NAME}.service" -n 30 --no-pager || true
  die "Установка завершилась с ошибкой запуска — см. лог выше."
fi
