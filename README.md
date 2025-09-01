# Telegram Recon Bot

> **Legal Notice:** Gunakan hanya untuk target yang kamu miliki hak/izin tertulis.

## Fitur
- Subdomain enumeration (subfinder)
- Port scanning (nmap)
- Directory brute-force (feroxbuster/dirsearch)
- Technology detection (whatweb)
- DNS info (dig)
- WHOIS lookup (whois)
- Quick chain (/all <domain>)

## Instalasi
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Konfigurasi
Buat file `.env` atau `/etc/default/telegram-recon-bot`:
```bash
TELEGRAM_TOKEN=123456:ABC...
ALLOWLIST=123456789
TIMEOUT_CMD=240
MAX_BYTES=800000
```

## Menjalankan
```bash
source .venv/bin/activate
python bot.py
```

## Systemd Service
Lihat file `setup.sh` untuk otomatisasi.
