#!/usr/bin/env python3
"""
Telegram Recon Bot (versi stabil)
---------------------------------
Fitur:
- /subdomains <domain>   -> subfinder
- /ports <host|domain>   -> nmap
- /dir <url>             -> feroxbuster (fallback dirsearch)
- /tech <url>            -> whatweb
- /dns <domain>          -> dig (A, AAAA, NS, MX, TXT)
- /whois <domain>        -> whois
- /all <domain>          -> chain cepat (subfinder + nmap top1000 + DNS ANY + WHOIS)
- /id                    -> tampilkan Telegram user ID
- /ping                  -> uji respons bot

⚠️ Gunakan HANYA pada target yang Anda miliki izin tertulis.

ENV:
- TELEGRAM_TOKEN (wajib)
- ALLOWLIST="123,456" (opsional, kosongkan untuk izinkan semua)
- TIMEOUT_CMD=180 (opsional)
- MAX_BYTES=800000 (opsional, pembatas ukuran output dalam byte)
"""

import asyncio
import os
import re
import textwrap
from io import BytesIO
from typing import List, Tuple

from dotenv import load_dotenv
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ---------- Konfigurasi ----------
load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
ALLOWLIST = set([x.strip() for x in os.getenv("ALLOWLIST", "").split(",") if x.strip()])
TIMEOUT_CMD = int(os.getenv("TIMEOUT_CMD", "180"))
MAX_BYTES = int(os.getenv("MAX_BYTES", str(800_000)))

# Validasi domain/URL (lebih permisif tapi aman)
DOMAIN_CHARS_RE = re.compile(r"^[A-Za-z0-9.-]+$")  # huruf, angka, titik, dash
URL_RE = re.compile(r"^(https?://)([^/\s]+)(/.*)?$", re.IGNORECASE)

# Batas aman untuk pesan Telegram (4096 char limit)
MAX_TG = 3900  # sisakan margin untuk Markdown


# ---------- Utilitas ----------
def _is_allowed(user_id: int) -> bool:
    if not ALLOWLIST:
        return True
    return str(user_id) in ALLOWLIST


def validate_domain(domain: str) -> bool:
    """
    Validasi longgar: karakter diperbolehkan + minimal ada titik, tidak diawali/diakhiri titik.
    """
    if not domain:
        return False
    domain = domain.strip().lower()
    if domain.startswith(".") or domain.endswith("."):
        return False
    if "." not in domain:
        return False
    if not DOMAIN_CHARS_RE.match(domain):
        return False
    return True


def validate_url(url: str) -> bool:
    return bool(URL_RE.match(url.strip()))


def format_block(title: str, content: str) -> str:
    content = (content or "").strip() or "(no output)"
    # Markdown legacy (PTB ParseMode.MARKDOWN) mendukung triple backticks
    return f"*{title}*\n```\n{content}\n```"


def _ellipsize(data: bytes, limit: int = MAX_BYTES) -> bytes:
    if len(data) <= limit:
        return data
    suffix = b"\n\n[Output truncated due to size limit]\n"
    return data[: max(0, limit - len(suffix))] + suffix


async def run_cmd(cmd: List[str], timeout: int = TIMEOUT_CMD) -> Tuple[int, bytes, bytes]:
    """Jalankan command CLI dengan timeout & tangkap stdout/stderr."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return 124, b"", b"Command timed out\n"
        return proc.returncode, stdout, stderr
    except FileNotFoundError:
        return 127, b"", f"Command not found: {cmd[0]}\n".encode()
    except Exception as e:
        return 1, b"", f"Execution error: {e}\n".encode()


async def send_long_markdown(update: Update, text: str):
    """
    Kirim teks panjang:
      - jika <= MAX_TG → kirim langsung
      - jika > MAX_TG → pecah ke beberapa pesan
      - jika potongan terlalu banyak → kirim sebagai file .txt
    """
    if len(text) <= MAX_TG:
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
        return

    lines = text.splitlines(keepends=True)
    buf, cur = [], 0
    chunks = []
    for ln in lines:
        ln_len = len(ln)
        if cur + ln_len > MAX_TG:
            chunks.append("".join(buf))
            buf = [ln]
            cur = ln_len
        else:
            buf.append(ln)
            cur += ln_len
    if buf:
        chunks.append("".join(buf))

    # Terlalu banyak potongan -> kirim dokumen
    if len(chunks) > 6:
        bio = BytesIO(text.encode())
        bio.name = "output.txt"
        await update.message.reply_document(
            document=bio,
            caption="Output panjang, dikirim sebagai file.",
        )
        return

    for c in chunks:
        piece = c.strip()
        await update.message.reply_text(piece, parse_mode=ParseMode.MARKDOWN)


# ---------- Commands ----------
async def ensure_auth(update: Update) -> bool:
    user = update.effective_user
    if user and not _is_allowed(user.id):
        await update.message.reply_text("❌ Not authorized.")
        return False
    return True


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    msg = textwrap.dedent(
        """
        👋 *Telegram Recon Bot*
        ⚠️ Gunakan hanya untuk tujuan legal.

        Perintah:
        /subdomains <domain>
        /ports <host|domain>
        /dir <url>
        /tech <url>
        /dns <domain>
        /whois <domain>
        /all <domain>
        /id
        /ping
        """
    ).strip()
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id if update.effective_user else None
    await update.message.reply_text(f"Your Telegram user ID: {uid}")


async def cmd_ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("pong ✅")


async def cmd_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /subdomains <domain>")
        return
    domain = context.args[0].strip().lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    await update.message.reply_text(f"🔎 Subdomain enumeration: {domain}")
    rc, out, err = await run_cmd(["subfinder", "-silent", "-d", domain], timeout=max(TIMEOUT_CMD, 180))
    text = format_block("subfinder", _ellipsize(out).decode(errors="ignore"))
    if err:
        text += "\n" + format_block("stderr", err.decode(errors="ignore"))
    await send_long_markdown(update, text)

    # (opsional) kirim raw sebagai file jika ada output berarti
    if out and out.strip():
        bio = BytesIO(out)
        bio.name = f"subfinder_{domain}.txt"
        await update.message.reply_document(bio, caption=f"Raw subfinder output for {domain}")


async def cmd_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /ports <host|domain>")
        return
    target = context.args[0].strip()

    await update.message.reply_text(f"🛠️ Nmap scanning {target} (full TCP) …")
    rc, out, err = await run_cmd(
        ["nmap", "-sV", "-Pn", "-T4", "-p-", "--min-rate", "1000", target],
        timeout=max(TIMEOUT_CMD, 240),
    )
    text = format_block("nmap", _ellipsize(out).decode(errors="ignore"))
    if err:
        text += "\n" + format_block("stderr", err.decode(errors="ignore"))
    await send_long_markdown(update, text)


async def cmd_dir(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /dir <url>")
        return
    url = context.args[0].strip()
    if not validate_url(url):
        await update.message.reply_text("❌ Invalid URL. Contoh: https://example.com")
        return

    await update.message.reply_text(f"🧭 Directory brute-force on {url} …")
    # Prefer feroxbuster, fallback dirsearch
    rc, _, _ = await run_cmd(["which", "feroxbuster"])
    if rc == 0:
        cmd = ["feroxbuster", "-u", url, "-n", "-q", "--silent"]
        title = "feroxbuster"
    else:
        # dirsearch perlu sudah terpasang & disymlink ke PATH
        cmd = ["dirsearch", "-u", url, "-e", "*", "--plain-text-report=/dev/stdout"]
        title = "dirsearch"

    rc, out, err = await run_cmd(cmd, timeout=max(TIMEOUT_CMD, 300))
    text = format_block(title, _ellipsize(out).decode(errors="ignore"))
    if err:
        text += "\n" + format_block("stderr", err.decode(errors="ignore"))
    await send_long_markdown(update, text)


async def cmd_tech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /tech <url>")
        return
    url = context.args[0].strip()
    if not validate_url(url):
        await update.message.reply_text("❌ Invalid URL. Contoh: https://example.com")
        return

    await update.message.reply_text(f"🔬 Technology detection: {url}")
    rc, out, err = await run_cmd(["whatweb", "-v", url], timeout=max(TIMEOUT_CMD, 120))
    text = format_block("whatweb", _ellipsize(out).decode(errors="ignore"))
    if err:
        text += "\n" + format_block("stderr", err.decode(errors="ignore"))
    await send_long_markdown(update, text)


async def cmd_dns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /dns <domain>")
        return
    domain = context.args[0].strip().lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    await update.message.reply_text(f"🧾 DNS records for {domain}")
    # rangkum record utama + ANY (diagnostik)
    records = [
        ("A", ["dig", "+short", domain, "A"]),
        ("AAAA", ["dig", "+short", domain, "AAAA"]),
        ("NS", ["dig", "+short", domain, "NS"]),
        ("MX", ["dig", "+short", domain, "MX"]),
        ("TXT", ["dig", "+short", domain, "TXT"]),
    ]
    parts = []
    for title, cmd in records:
        rc, out, _ = await run_cmd(cmd)
        parts.append(f"{title}:\n{(out.decode(errors='ignore') or '(none)').strip()}")
    msg = format_block("dig", "\n\n".join(parts))
    await send_long_markdown(update, msg)

    # ANY (kadang dibatasi provider DNS)
    rc, out, err = await run_cmd(["dig", domain, "ANY", "+noall", "+answer"])
    msg2 = format_block("dig ANY", (out.decode(errors="ignore") or "(none)").strip())
    if err:
        msg2 += "\n" + format_block("stderr", err.decode(errors="ignore"))
    await send_long_markdown(update, msg2)


async def cmd_whois(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /whois <domain>")
        return
    domain = context.args[0].strip().lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    await update.message.reply_text(f"📇 WHOIS for {domain}")
    rc, out, err = await run_cmd(["whois", domain], timeout=max(TIMEOUT_CMD, 120))
    text = format_block("whois", _ellipsize(out).decode(errors="ignore"))
    if err:
        text += "\n" + format_block("stderr", err.decode(errors="ignore"))
    await send_long_markdown(update, text)


async def cmd_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await ensure_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: /all <domain>")
        return
    domain = context.args[0].strip().lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    await update.message.reply_text(f"🚀 Quick recon on {domain}")

    # 1) subfinder
    rc, out, _ = await run_cmd(["subfinder", "-silent", "-d", domain], timeout=max(TIMEOUT_CMD, 180))
    await send_long_markdown(update, format_block("subfinder", _ellipsize(out).decode(errors="ignore")))

    # 2) nmap top 1000
    rc, out, _ = await run_cmd(["nmap", "-sV", "-Pn", "-T4", "--top-ports", "1000", domain], timeout=max(TIMEOUT_CMD, 240))
    await send_long_markdown(update, format_block("nmap (top 1000)", _ellipsize(out).decode(errors="ignore")))

    # 3) dig ANY
    rc, out, _ = await run_cmd(["dig", domain, "ANY", "+noall", "+answer"])
    await send_long_markdown(update, format_block("dig ANY", _ellipsize(out).decode(errors="ignore")))

    # 4) whois
    rc, out, _ = await run_cmd(["whois", domain], timeout=max(TIMEOUT_CMD, 120))
    await send_long_markdown(update, format_block("whois", _ellipsize(out).decode(errors="ignore")))


async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Unknown command. Use /help")


# ---------- Main ----------
def build_app():
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_TOKEN env var is required")
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .build()
    )

    app.add_handler(CommandHandler(["start", "help"], cmd_start))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("ping", cmd_ping))

    app.add_handler(CommandHandler("subdomains", cmd_subdomains))
    app.add_handler(CommandHandler("ports", cmd_ports))
    app.add_handler(CommandHandler("dir", cmd_dir))
    app.add_handler(CommandHandler("tech", cmd_tech))
    app.add_handler(CommandHandler("dns", cmd_dns))
    app.add_handler(CommandHandler("whois", cmd_whois))
    app.add_handler(CommandHandler("all", cmd_all))

    app.add_handler(MessageHandler(filters.COMMAND, unknown))
    return app


if __name__ == "__main__":
    application = build_app()
    application.run_polling(close_loop=False)
