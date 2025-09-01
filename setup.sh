#!/usr/bin/env bash
set -euo pipefail

ENVFILE="/etc/default/telegram-recon-bot"
UNIT="/etc/systemd/system/telegram-recon-bot.service"

read -rp "Telegram Bot Token: " BOT_TOKEN
read -rp "Allowlist (opsional, koma-separasi; kosongkan bila bebas): " ALLOWLIST
read -rp "User linux non-root [botuser]: " SVC_USER
SVC_USER=${SVC_USER:-botuser}
read -rp "Workdir proyek [/opt/telegram-recon-bot]: " WORKDIR
WORKDIR=${WORKDIR:-/opt/telegram-recon-bot}
VENV="$WORKDIR/.venv"

sudo mkdir -p "$WORKDIR"
sudo rsync -a --delete --exclude .git ./ "$WORKDIR/"

if ! id "$SVC_USER" &>/dev/null; then
  sudo useradd -r -s /usr/sbin/nologin "$SVC_USER"
fi

sudo -u "$SVC_USER" bash -c "python3 -m venv '$VENV' || true"
sudo -u "$SVC_USER" bash -c "source '$VENV/bin/activate' && pip install -U pip && pip install -r '$WORKDIR/requirements.txt'"

sudo tee "$ENVFILE" >/dev/null <<ENV
TELEGRAM_TOKEN=$BOT_TOKEN
ALLOWLIST=$ALLOWLIST
TIMEOUT_CMD=240
MAX_BYTES=800000
WORKDIR=$WORKDIR
VENV=$VENV
USER=$SVC_USER
ENV

sudo chown -R "$SVC_USER:$SVC_USER" "$WORKDIR"

sudo tee "$UNIT" >/dev/null <<'UNIT'
[Unit]
Description=Telegram Recon Bot
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/default/telegram-recon-bot
User=%i
WorkingDirectory=${WORKDIR}
ExecStart=${VENV}/bin/python ${WORKDIR}/bot.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT

sudo sed -i "s/^User=%i/User=$SVC_USER/" "$UNIT"

sudo systemctl daemon-reload
sudo systemctl enable --now telegram-recon-bot
sudo systemctl status telegram-recon-bot -n 50 --no-pager || true
