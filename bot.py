#!/usr/bin/env python3
"""
Telegram Recon Bot
------------------
Bot Telegram untuk melakukan website enumeration (reconnaissance).

Fitur:
- Subdomain enumeration (subfinder)
- Port scanning (nmap)
- Directory brute-force (feroxbuster / dirsearch)
- Technology detection (whatweb)
- DNS info (dig)
- WHOIS lookup
- Chain cepat (subdomain + nmap + DNS + WHOIS)

⚠️ Gunakan hanya untuk tujuan legal.
"""

import asyncio
import os
import re
import shlex
import textwrap
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
    AIORateLimiter,
)

# --- Load konfigurasi dari .env / environment ---
load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
ALLOWLIST = set([x.strip() for x in os.getenv("ALLOWLIST", "").split(",") if x.strip()])
TIMEOUT_CMD = int(os.getenv("TIMEOUT_CMD", "180"))
MAX_BYTES = int(os.getenv("MAX_BYTES", str(800_000)))

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,63}$")
URL_RE = re.compile(r"^(https?://)([^/]+)(/.*)?$")


# --- Helper ---
def _is_allowed(user_id: int) -> bool:
    if not ALLOWLIST:
        return True
    return str(user_id) in ALLOWLIST


def _ellipsize(data: bytes, limit: int = MAX_BYTES) -> bytes:
    if len(data) <= limit:
        return data
    suffix = b"\n\n[Output truncated]\n"
    return data[: max(0, limit - len(suffix))] + suffix


async def run_cmd(cmd: List[str], timeout: int = TIMEOUT_CMD) -> Tuple[int, bytes, bytes]:
    """Jalankan perintah sistem dengan timeout"""
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


def format_block(title: str, content: str) -> str:
    content = content.strip() or "(no output)"
    return f"*{title}*\n```\n{content}\n```"


def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def validate_url(url: str) -> bool:
    return bool(URL_RE.match(url))


# --- Commands ---
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    msg = textwrap.dedent("""
    👋 *Telegram Recon Bot*
    ⚠️ Gunakan hanya untuk tujuan legal.

    Perintah yang tersedia:
    /subdomains <domain>
    /ports <host>
    /dir <url>
    /tech <url>
    /dns <domain>
    /whois <domain>
    /all <domain>
    """)
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /subdomains <domain>")
        return
    domain = context.args[0].lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    await update.message.reply_text(f"🔎 Subdomain enumeration: {domain}")
    rc, out, err = await run_cmd(["subfinder", "-silent", "-d", domain])
    msg = format_block("subfinder", _ellipsize(out).decode())
    if err:
        msg += "\n" + format_block("stderr", err.decode())
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /ports <host>")
        return
    target = context.args[0]

    await update.message.reply_text(f"🛠️ Nmap scanning {target} ...")
    rc, out, err = await run_cmd(
        ["nmap", "-sV", "-Pn", "-T4", "-p-", "--min-rate", "1000", target],
        timeout=240,
    )
    msg = format_block("nmap", _ellipsize(out).decode())
    if err:
        msg += "\n" + format_block("stderr", err.decode())
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_dir(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /dir <url>")
        return
    url = context.args[0]
    if not validate_url(url):
        await update.message.reply_text("❌ Invalid URL.")
        return

    await update.message.reply_text(f"🧭 Directory brute-force on {url}")
    rc, _, _ = await run_cmd(["which", "feroxbuster"])
    if rc == 0:
        cmd = ["feroxbuster", "-u", url, "-n", "-q", "--silent"]
        title = "feroxbuster"
    else:
        cmd = ["dirsearch", "-u", url, "-e", "*", "--plain-text-report=/dev/stdout"]
        title = "dirsearch"

    rc, out, err = await run_cmd(cmd, timeout=300)
    msg = format_block(title, _ellipsize(out).decode())
    if err:
        msg += "\n" + format_block("stderr", err.decode())
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_tech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /tech <url>")
        return
    url = context.args[0]
    if not validate_url(url):
        await update.message.reply_text("❌ Invalid URL.")
        return

    rc, out, err = await run_cmd(["whatweb", "-v", url])
    msg = format_block("whatweb", _ellipsize(out).decode())
    if err:
        msg += "\n" + format_block("stderr", err.decode())
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_dns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /dns <domain>")
        return
    domain = context.args[0].lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    parts = []
    for record in ["A", "AAAA", "NS", "MX", "TXT"]:
        rc, out, err = await run_cmd(["dig", "+short", domain, record])
        parts.append(f"{record}: {out.decode().strip() or '(none)'}")
    msg = format_block("dig", "\n".join(parts))
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_whois(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /whois <domain>")
        return
    domain = context.args[0].lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    rc, out, err = await run_cmd(["whois", domain])
    msg = format_block("whois", _ellipsize(out).decode())
    if err:
        msg += "\n" + format_block("stderr", err.decode())
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_allowed(update.effective_user.id):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /all <domain>")
        return
    domain = context.args[0].lower()
    if not validate_domain(domain):
        await update.message.reply_text("❌ Invalid domain.")
        return

    await update.message.reply_text(f"🚀 Quick recon on {domain}")

    # Subfinder
    rc, out, _ = await run_cmd(["subfinder", "-silent", "-d", domain])
    msg1 = format_block("subfinder", _ellipsize(out).decode())

    # Nmap (top 1000)
    rc, out, _ = await run_cmd(["nmap", "-sV", "-Pn", "-T4", "--top-ports", "1000", domain], timeout=240)
    msg2 = format_block("nmap", _ellipsize(out).decode())

    # DNS ANY
    rc, out, _ = await run_cmd(["dig", domain, "ANY", "+noall", "+answer"])
    msg3 = format_block("dig ANY", _ellipsize(out).decode())

    # WHOIS
    rc, out, _ = await run_cmd(["whois", domain])
    msg4 = format_block("whois", _ellipsize(out).decode())

    for chunk in [msg1, msg2, msg3, msg4]:
        await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN)


async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Unknown command. Use /help")


# --- Main ---
def build_app():
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_TOKEN required")
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .rate_limiter(AIORateLimiter(max_retries=3))
        .build()
    )

    app.add_handler(CommandHandler(["start", "help"], cmd_start))
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
