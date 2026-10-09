"""Outgoing email, delivered by Nodemailer (``mailer/send-mail.js``).

The portal itself stays stdlib-only: for each message Python starts a
short-lived ``node send-mail.js`` and hands it the transport options and the
message as JSON on stdin (so the SMTP password never appears in argv or the
environment).  Nodemailer then speaks SMTP with TLS -- implicit TLS on port
465 or STARTTLS (required, never optional) on 587 -- and verifies the
server certificate.

Setup: Node.js >= 20 on PATH (or PQVPN_NODE=/path/to/node) and
``npm ci --omit=dev`` once in ``pqvpn/portal/mailer``.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess

MAILER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailer")
SCRIPT = os.path.join(MAILER_DIR, "send-mail.js")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

# Defaults suit Gmail (smtp.gmail.com, SSL on 465, sign in with an App Password).
DEFAULT_SETTINGS = {"smtp_host": "smtp.gmail.com", "smtp_port": "465", "smtp_security": "ssl",
                    "smtp_user": "", "smtp_password": "", "mail_from_name": ""}


class MailError(Exception):
    pass


def valid_email(address: str) -> bool:
    return len(address) <= 254 and bool(EMAIL_RE.match(address))


def node_binary() -> str | None:
    return os.environ.get("PQVPN_NODE") or shutil.which("node") or shutil.which("nodejs")


def nodemailer_installed() -> bool:
    return os.path.isfile(os.path.join(MAILER_DIR, "node_modules", "nodemailer", "package.json"))


def status() -> dict:
    """What the admin settings page shows about the mail pipeline."""
    node, version = node_binary(), None
    if node:
        try:
            version = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            node = None
    nm = None
    if nodemailer_installed():
        with open(os.path.join(MAILER_DIR, "node_modules", "nodemailer", "package.json"), encoding="utf-8") as f:
            nm = json.load(f).get("version")
    return {"node": node, "node_version": version, "nodemailer": nm}


def is_configured(settings: dict) -> bool:
    return bool(settings.get("smtp_host") and settings.get("smtp_user") and settings.get("smtp_password"))


def smtp_transport(settings: dict) -> dict:
    """Nodemailer SMTP transport options from the portal's email settings."""
    port = int(settings.get("smtp_port") or 465)
    ssl = (settings.get("smtp_security") or "ssl") == "ssl"
    return {"host": settings["smtp_host"], "port": port, "secure": ssl, "requireTLS": not ssl,
            "auth": {"user": settings["smtp_user"], "pass": settings["smtp_password"]},
            "tls": {"minVersion": "TLSv1.2"}}


def sender(settings: dict, issuer: str) -> dict:
    return {"name": settings.get("mail_from_name") or issuer, "address": settings["smtp_user"]}


def internal_address(host: str) -> bool:
    """True for loopback/private/link-local/reserved IP literals and "localhost" (no DNS lookup)."""
    if host.lower().rstrip(".") == "localhost" or host.lower().endswith(".localhost"):
        return True
    try:
        return not ipaddress.ip_address(host.split("%")[0]).is_global
    except ValueError:
        return False  # a host name: checked after resolution, at send time


def pin_public_host(transport: dict) -> dict:
    """Resolve the SMTP host once, refuse internal addresses, and connect to exactly that address.

    Stops the email settings from being used to reach services inside the server's network (SSRF) and closes
    the DNS-rebinding gap between this check and Nodemailer's own lookup.  TLS is still verified against the
    configured host name (``tls.servername``).
    """
    host, port = transport["host"], int(transport["port"])
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise MailError(f"cannot resolve {host}: {exc}") from None
    addrs = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]
    if not addrs or any(not a.is_global for a in addrs):
        raise MailError(f"{host} resolves to an internal address; the portal only sends through public mail "
                        "servers (set allow_internal_smtp = true in portal.toml for a local relay)")
    return {**transport, "host": str(addrs[0]),
            "tls": {**transport.get("tls", {}), "servername": transport.get("tls", {}).get("servername", host)}}


def send(transport: dict, message: dict, timeout: float = 60, allow_internal: bool = False) -> dict:
    """Deliver one message through Nodemailer; raises MailError with a readable reason."""
    if transport.get("host") and not allow_internal:
        transport = pin_public_host(transport)
    node = node_binary()
    if not node:
        raise MailError("Node.js is not installed (Nodemailer needs Node.js 20 or newer)")
    if not nodemailer_installed():
        raise MailError(f"Nodemailer is not installed: run `npm ci --omit=dev` in {MAILER_DIR}")
    try:
        proc = subprocess.run([node, SCRIPT], input=json.dumps({"transport": transport, "message": message}),
                              capture_output=True, text=True, encoding="utf-8", timeout=timeout, cwd=MAILER_DIR)
    except subprocess.TimeoutExpired:
        raise MailError("timed out while talking to the mail server") from None
    except OSError as exc:
        raise MailError(f"cannot run Node.js: {exc}") from None
    if proc.returncode != 0:
        raise MailError((proc.stderr.strip() or f"mailer exited with code {proc.returncode}")[:400])
    try:
        return json.loads(proc.stdout or "{}")
    except ValueError:
        return {}


# ------------------------------------------------------------------ messages

def _html(issuer: str, heading: str, paragraphs: list[str], code: str = "", note: str = "") -> str:
    """Email-client-safe HTML: tables and inline styles only.  ``paragraphs``/``note`` are trusted markup."""
    e = html.escape
    body = "".join(f'<p style="margin:0 0 14px;color:#334155;font-size:15px;line-height:1.5">{p}</p>'
                   for p in paragraphs)
    code_block = (f'<p style="margin:6px 0 20px;font:700 32px/1.2 Consolas,Menlo,monospace;letter-spacing:8px;'
                  f'color:#1e1b4b;background:#eef2ff;border-radius:10px;padding:14px 0;text-align:center">'
                  f'{e(code)}</p>') if code else ""
    note = f"{note}<br><br>" if note else ""
    return (f'<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Segoe UI,Arial,sans-serif">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" '
            f'style="padding:28px 12px"><table role="presentation" width="100%" style="max-width:480px;'
            f'background:#ffffff;border:1px solid #e2e8f0;border-radius:14px"><tr><td style="background:#1e1b4b;'
            f'color:#ffffff;padding:16px 24px;border-radius:14px 14px 0 0;font-weight:700;font-size:18px">'
            f'&#128737; {e(issuer)}</td></tr><tr><td style="padding:24px">'
            f'<h1 style="margin:0 0 14px;font-size:20px;color:#0f172a">{e(heading)}</h1>{body}{code_block}'
            f'<p style="margin:0;color:#64748b;font-size:12.5px">{note}This is an automated message from '
            f'{e(issuer)}.</p></td></tr></table></td></tr></table></body></html>')


def reset_code_message(issuer: str, username: str, code: str, minutes: int, ip: str) -> dict:
    e = html.escape
    text = (f"Hello {username},\n\nYour {issuer} password reset code is:\n\n    {code}\n\n"
            f"It expires in {minutes} minutes and works once. The request came from IP address {ip}.\n"
            "If you did not ask to reset your password, ignore this email: your password stays unchanged.\n")
    return {"subject": f"{code} is your {issuer} password reset code", "text": text,
            "html": _html(issuer, "Reset your password", [
                f"Hello <strong>{e(username)}</strong>,", "Use this code to choose a new password:"], code,
                note=f"The code expires in {minutes} minutes and works once. Requested from IP {e(ip)}. "
                     "If this wasn't you, ignore this email &mdash; your password stays unchanged.")}


def password_changed_message(issuer: str, username: str, ip: str, when: str) -> dict:
    e = html.escape
    text = (f"Hello {username},\n\nThe password of your {issuer} account was changed with an emailed reset "
            f"code on {when} from IP address {ip}.\nAll signed-in sessions were signed out.\n\n"
            "If this wasn't you, contact your administrator immediately.\n")
    return {"subject": f"Your {issuer} password was changed", "text": text,
            "html": _html(issuer, "Your password was changed", [
                f"Hello <strong>{e(username)}</strong>,",
                f"The password of your account was changed with an emailed reset code on {e(when)} "
                f"from IP address {e(ip)}. All signed-in sessions were signed out.",
                "<strong>If this wasn't you, contact your administrator immediately.</strong>"])}


def test_message(issuer: str, admin: str) -> dict:
    text = (f"This test email was sent by {admin} from the {issuer} admin settings.\n"
            "Email delivery works: password-reset codes will arrive like this one.\n")
    return {"subject": f"{issuer}: test email", "text": text,
            "html": _html(issuer, "Email delivery works", [
                f"This test email was sent by <strong>{html.escape(admin)}</strong> from the admin settings.",
                "Password-reset codes will arrive like this one."])}
