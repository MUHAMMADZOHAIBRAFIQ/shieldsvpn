"""pqvpn web portal: login, user self-service and administration.

Standards and practices applied
  * Authentication: scrypt passwords + optional/enforced TOTP (auth.py).
  * Sessions (OWASP Session Management): 256-bit random tokens, stored only as
    SHA-256 hashes, HttpOnly + SameSite=Strict cookies (+ Secure/__Host- with
    TLS), idle and absolute timeouts, rotation on login, revocation on logout,
    password change and account changes.
  * CSRF: synchronizer token on every state-changing form + Origin check.
  * Brute force: per-IP rate limiting and per-account lockout (NIST 800-63B 5.2.2).
  * Headers: strict Content-Security-Policy (no inline script), frame denial,
    nosniff, no-referrer, no-store, HSTS when served over TLS.
  * Output encoding: every dynamic value is HTML-escaped; live updates use
    textContent only.
  * Audit trail of all security-relevant events.
  * Access: by default only administrators may sign in (Settings -> Portal
    access); other accounts are VPN-only and get their profile from an admin.
  * Password recovery (OWASP Forgot Password): a single-use 6-digit code sent
    to the account's email, stored scrypt-hashed, valid 10 minutes, 5 guesses,
    resend throttling, identical responses whether or not the account exists,
    every session revoked on success and a notification email afterwards.
"""

from __future__ import annotations

import hmac
import html
import http.cookies
import http.server
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse

from .. import __version__, logo
from ..config import PortalConfig
from ..crypto.suites import describe_suite
from ..protocol import RateLimiter
from . import auth, firebase, mail, plans
from .qr import QrCode
from .service import CA, issue_profile
from .store import Store
from .vault import Vault

log = logging.getLogger("pqvpn.portal")
e = html.escape
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$")
MAX_FAILURES, LOCK_SECONDS = 5, 15 * 60
RESET_TTL, RESET_MAX_ATTEMPTS, RESET_RESEND_AFTER, RESET_MAX_PER_HOUR = 10 * 60, 5, 60, 5
DEVICE_TTL = 60 * 24 * 3600  # a browser stays a "known device" (for lockout scoping) for 60 days
# Settings sealed at rest with the vault (readable, so not hashable); re-sealed on start-up if found in plaintext.
SECRET_SETTINGS = ("smtp_password",)
REDACTED_ACTOR = "(unknown)"  # never store a typed login verbatim: it is sometimes a mistyped password
# "admins": only administrators may sign in; "everyone": users also sign in to download their own profile.
PORTAL_DEFAULTS = {"portal_access": "admins"}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
SECURITY_HEADERS = [
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    # Not "no-referrer": under it browsers send "Origin: null" on form POSTs and the Origin check (rightly)
    # rejects every sign-in.  "same-origin" still sends nothing to other sites.
    ("Referrer-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cache-Control", "no-store"),
]


def fmt_time(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"


def fmt_date(ts) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else ""


def last_day(expires) -> str:
    """plan_expires is the first second *after* the last paid day; show that last day."""
    return fmt_date(expires - 1) if expires else ""


def mask_email(address: str) -> str:
    local, _, domain = (address or "").partition("@")
    return f"{local[:2]}***@{domain}" if domain else "-"


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


class Portal:
    def __init__(self, cfg: PortalConfig):
        self.cfg = cfg
        self.store = Store(cfg.database)
        data_dir = os.path.dirname(os.path.abspath(cfg.database))
        self.vault = Vault(os.path.join(data_dir, Vault.KEY_FILE))
        self.tls = bool(cfg.tls_certificate)
        self.cookie_name = "__Host-pqvpn_session" if self.tls else "pqvpn_session"
        self.device_cookie_name = "__Host-pqvpn_device" if self.tls else "pqvpn_device"
        self.limiter = RateLimiter(rate=10 / 60, burst=10)
        self.limiter_lock = threading.Lock()
        self.allowed_hosts = self._build_allowed_hosts()
        self._ca: CA | None = None
        self._ca_lock = threading.Lock()
        self.favicon = logo.render_ico("brand", sizes=(16, 32, 48))
        self.servers: list[http.server.ThreadingHTTPServer] = []
        self.mailer = mail.send  # (transport, message, timeout, allow_internal) -> info; tests swap in a fake
        self.mirror = firebase.Mirror(
            self.store, os.path.join(data_dir, firebase.KEY_FILE),
            self.settings, {"issuer": cfg.issuer, "server_name": cfg.server_name, "endpoint": cfg.endpoint,
                            "subnet": cfg.subnet})
        self._reseal_secrets()

    def _build_allowed_hosts(self) -> set[str]:
        """Host names the portal answers to -- checked on every request to block DNS-rebinding."""
        hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}
        for host, _port in self.cfg.listen:
            hosts.add(host.lower())
        for url in (self.cfg.public_url, self.cfg.vpn_portal_url):
            netloc = urllib.parse.urlsplit(url).hostname
            if netloc:
                hosts.add(netloc.lower())
        hosts.update(self.cfg.allowed_hosts)
        return hosts

    def host_allowed(self, host_header: str) -> bool:
        if not host_header:
            return True  # HTTP/1.0 without Host; the Origin/CSRF checks still apply
        host = host_header.rsplit(":", 1)[0].lower() if not host_header.endswith("]") else host_header.lower()
        return host in self.allowed_hosts

    def _reseal_secrets(self) -> None:
        raw = self.store.settings()
        reseal = {k: self.vault.seal(k, raw[k]) for k in SECRET_SETTINGS
                  if raw.get(k) and not Vault.is_sealed(raw[k])}
        if reseal:
            self.store.set_settings(reseal)
            log.info("re-sealed %d plaintext secret(s) in the database", len(reseal))

    def settings(self) -> dict:
        s = self.store.settings({**mail.DEFAULT_SETTINGS, **plans.DEFAULT_SETTINGS, **PORTAL_DEFAULTS})
        for k in SECRET_SETTINGS:
            if s.get(k):
                try:
                    s[k] = self.vault.open(k, s[k])
                except Exception as exc:  # noqa: BLE001 -- a broken key must not take the whole portal down
                    log.error("cannot decrypt setting %s: %s", k, exc)
                    s[k] = ""
        return s

    def admins_only(self) -> bool:
        return self.settings()["portal_access"] != "everyone"

    def may_sign_in(self, user: dict) -> bool:
        return user["role"] == "admin" or not self.admins_only()

    def send_email(self, to: str, msg: dict) -> dict:
        settings = self.settings()
        if not mail.is_configured(settings):
            raise mail.MailError("email is not set up (Admin > Settings > Email)")
        return self.mailer(mail.smtp_transport(settings), {"from": mail.sender(settings, self.cfg.issuer),
                                                           "to": to, **msg},
                           allow_internal=self.cfg.allow_internal_smtp)

    def send_email_async(self, to: str, msg: dict, purpose: str, actor: str, ip: str) -> threading.Thread:
        """Deliver in the background: responses must not reveal (by timing) whether an email went out."""
        def run():
            try:
                self.send_email(to, msg)
                self.store.audit("email_sent", actor=actor, ip=ip, detail=f"{purpose} to {mask_email(to)}")
            except Exception as exc:  # noqa: BLE001 -- reported in the audit log for the admins
                log.warning("email (%s) to %s failed: %s", purpose, mask_email(to), exc)
                self.store.audit("email_failed", actor=actor, ip=ip, detail=f"{purpose} to {mask_email(to)}: {exc}")
        t = threading.Thread(target=run, name="portal-mail", daemon=True)
        t.start()
        return t

    @property
    def ca(self) -> CA:
        with self._ca_lock:
            if self._ca is None:
                self._ca = CA(self.cfg)
            return self._ca

    def allow_attempt(self, ip: str) -> bool:
        with self.limiter_lock:
            return self.limiter.allow(ip, time.monotonic())

    # -------------------------------------------------------------- serving
    def _bind_allowed(self, host: str) -> bool:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or self.tls or ip in ipaddress.ip_network(self.cfg.subnet):
            return True
        return self.cfg.allow_insecure_http

    def start(self) -> list[str]:
        urls = []
        for host, port in self.cfg.listen:
            if not self._bind_allowed(host):
                raise SystemExit(f"refusing to serve the portal over plain HTTP on {host}: configure "
                                 "tls_certificate/tls_private_key, or listen on loopback / the VPN subnet")
            srv = _make_server(host, port, self)
            if self.tls:
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(self.cfg.tls_certificate, self.cfg.tls_private_key)
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
            threading.Thread(target=srv.serve_forever, name=f"portal-{host}:{port}", daemon=True).start()
            self.servers.append(srv)
            shown = f"[{host}]" if ":" in host else host
            urls.append(f"{'https' if self.tls else 'http'}://{shown}:{srv.server_address[1]}/")
        return urls

    def stop(self) -> None:
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()


def _make_server(host: str, port: int, portal: Portal):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    class Server(http.server.ThreadingHTTPServer):
        address_family = family
        daemon_threads = True

        def server_bind(self):
            # The VPN tunnel address may not exist yet when the portal starts, so bind it anyway (FREEBIND).
            # socket.IP_FREEBIND is not exposed by every Python build; fall back to its Linux value (15) so a
            # missing constant does not make binding a not-yet-present tunnel address fail with EADDRNOTAVAIL.
            if family == socket.AF_INET:
                try:
                    self.socket.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_FREEBIND", 15), 1)
                except OSError:
                    pass  # not Linux, or not permitted; bind() below will report any real problem
            super().server_bind()

    handler = type("BoundHandler", (Handler,), {"portal": portal})
    return Server((host, port), handler)


# ====================================================================== request handling

class Handler(http.server.BaseHTTPRequestHandler):
    portal: Portal
    server_version = "pqvpn-portal"
    sys_version = ""
    timeout = 30

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(10)
            self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    # -------------------------------------------------------------- plumbing
    @property
    def ip(self) -> str:
        return self.client_address[0]

    def _dispatch(self, method: str) -> None:
        self.token = self.session = self.user = None
        self.query: dict[str, str] = {}
        try:
            if not self.portal.host_allowed(self.headers.get("Host", "")):
                # A foreign Host means a DNS-rebinding page is talking to us; refuse before doing any work.
                self.close_connection = True
                return self._error(421, "This server does not answer to that host name.")
            url = urllib.parse.urlsplit(self.path)
            self.query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            self.form: dict[str, str] = {}
            if method == "POST":
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = -1
                if not 0 <= length <= 65536:
                    self.close_connection = True
                    return self._error(413 if length > 0 else 400, "Request too large." if length > 0 else
                                       "Bad request.")
                # Read the body before any refusal: closing a socket with unread data makes the OS send a
                # TCP reset, and the browser would show a connection error instead of our answer.
                body = self.rfile.read(length).decode("utf-8", "replace")
                if not self._origin_ok():
                    return self._error(403, "Cross-site request blocked.")
                if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                    self.form = {k: v[0] for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()}
            self.token, self.session, self.user = self._load_session()
            for m, pattern, level, fn in ROUTES:
                if m != method:
                    continue
                match = re.fullmatch(pattern, url.path)
                if match:
                    if not self._authorize(level, url.path, method):
                        return
                    return fn(self, **match.groupdict())
            self._error(404, "Page not found.")
        except (ConnectionError, ssl.SSLError, TimeoutError):
            pass
        except Exception:
            log.exception("portal error on %s %s", method, self.path)
            try:
                self._error(500, "Internal error. The incident was logged.")
            except Exception:
                pass

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True  # non-browser clients; CSRF tokens still apply
        host = self.headers.get("Host", "")
        return urllib.parse.urlsplit(origin).netloc == host

    def _load_session(self):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None, None, None
        morsel = jar.get(self.portal.cookie_name)
        if not morsel or not morsel.value:
            return None, None, None
        cfg = self.portal.cfg
        s = self.portal.store.session(morsel.value, cfg.session_idle, cfg.session_max)
        if s is None:
            return None, None, None
        user = self.portal.store.user(s["user_id"])
        if user is None or not user["enabled"] or not self.portal.may_sign_in(user):
            self.portal.store.delete_session(morsel.value)
            return None, None, None
        return morsel.value, s, user

    def _authorize(self, level: str, path: str, method: str) -> bool:
        if level == "public":
            return True
        if self.session is None:
            if path.startswith("/api/"):
                self._json(401, {"error": "login required"})
            else:
                # Remember where they were headed (e.g. /admin typed in the address bar) and return there
                # after sign-in.  Only safe same-site paths are kept (see _safe_next).
                nxt = _safe_next(path) if method == "GET" and path != "/" else ""
                self._redirect("/login?next=" + urllib.parse.quote(nxt, safe="/") if nxt else "/login")
            return False
        if level == "any":  # any session, e.g. logout during the 2FA step
            pass
        elif level == "pending":
            if not self.session["pending_2fa"]:
                self._redirect("/")
                return False
        else:
            if self.session["pending_2fa"]:
                self._redirect("/login/2fa")
                return False
            u = self.user
            if u["must_change_password"] and path not in ("/account/password", "/logout"):
                self._redirect("/account/password")
                return False
            if (self.portal.cfg.require_2fa_for_admins and u["role"] == "admin" and not u["totp_enabled"]
                    and path not in ("/account/2fa", "/account/password", "/logout")):
                self._redirect("/account/2fa")
                return False
            if level == "admin" and u["role"] != "admin":
                self._error(403, "Administrators only.")
                return False
        # Compare as bytes: hmac.compare_digest raises TypeError on a non-ASCII str (a crafted token must not 500).
        if method == "POST" and not hmac.compare_digest(self.form.get("csrf", "").encode("utf-8"),
                                                         self.session["csrf"].encode("utf-8")):
            self._error(403, "Your session form expired. Please reload the page and try again.")
            return False
        return True

    def _audit(self, action: str, detail: str = "", actor: str | None = None) -> None:
        name = actor if actor is not None else (self.user["username"] if self.user else "")
        self.portal.store.audit(action, actor=name, ip=self.ip, detail=detail)

    # -------------------------------------------------------------- responses
    def _send(self, status: int, body: bytes, ctype: str, headers: list[tuple[str, str]] = ()) -> None:
        self.send_response(status)
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        if self.portal.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, title: str, content: str, status: int = 200, headers=()) -> None:
        self._send(status, layout(self.portal, title, content, self.user if self.session and not
                                  self.session["pending_2fa"] else None,
                                  self.session["csrf"] if self.session else "").encode(), "text/html; charset=utf-8",
                   headers)

    def _json(self, status: int, data) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def _redirect(self, location: str, headers=()) -> None:
        self._send(303, b"", "text/plain", [("Location", location), *headers])

    def _error(self, status: int, message: str) -> None:
        self._html("Error", f'<section class="card narrow"><h1>{status}</h1><p>{e(message)}</p>'
                            f'<p><a class="btn" href="/">Back</a></p></section>', status)

    def _cookie(self, token: str, max_age: int | None = None) -> tuple[str, str]:
        parts = [f"{self.portal.cookie_name}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if self.portal.tls:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "Set-Cookie", "; ".join(parts)

    def _read_cookie(self, name: str) -> str | None:
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel and morsel.value else None

    def _device_cookie(self, token: str) -> tuple[str, str]:
        parts = [f"{self.portal.device_cookie_name}={token}", "Path=/", "HttpOnly", "SameSite=Strict",
                 f"Max-Age={DEVICE_TTL}"]
        if self.portal.tls:
            parts.append("Secure")
        return "Set-Cookie", "; ".join(parts)

    def _known_device(self, user_id: int) -> dict | None:
        token = self._read_cookie(self.portal.device_cookie_name)
        return self.portal.store.device(token, user_id, DEVICE_TTL) if token else None

    def _new_session(self, user: dict, pending_2fa: bool) -> tuple[str, str]:
        if self.token:  # rotate: never reuse a pre-authentication session
            self.portal.store.delete_session(self.token)
        token, _csrf = self.portal.store.create_session(user["id"], self.ip, self.headers.get("User-Agent", ""),
                                                       pending_2fa)
        return self._cookie(token)


# ====================================================================== pages

def layout(portal: Portal, title: str, content: str, user: dict | None, csrf: str) -> str:
    nav = ""
    if user:
        # The admin area is deliberately not linked here; administrators reach it by typing /admin in the
        # address bar.  So the menu looks the same for everyone and the admin pages are not advertised.
        links = [("/", "Dashboard"), ("/account", "Account")]
        items = "".join(f'<a href="{href}">{label}</a>' for href, label in links)
        nav = (f'<nav>{items}<span class="who">{e(user["username"])}'
               f'<span class="badge {e(user["role"])}">{e(user["role"])}</span></span>'
               f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{e(csrf)}">'
               f'<button class="link">Sign out</button></form></nav>')
    issuer = e(portal.cfg.issuer)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} &middot; {issuer}</title><link rel="icon" href="/favicon.ico">
<link rel="stylesheet" href="/static/style.css"></head><body>
<header class="top"><a class="brand" href="/">{logo.svg("brand", 34, "hdr")}<span>{issuer}</span>
<small>post-quantum VPN</small></a>{nav}</header>
<main>{content}</main>
<footer>{issuer} {__version__} &middot; ML-KEM-768 + X25519 key exchange &middot; ML-DSA-65 identities &middot;
SLH-DSA root of trust</footer>
<script src="/static/app.js"></script></body></html>"""


def _csrf_field(h: Handler) -> str:
    return f'<input type="hidden" name="csrf" value="{e(h.session["csrf"])}">'


def _safe_next(raw: str) -> str:
    """A validated same-site redirect target, so ?next= cannot be used for an open redirect.

    Keeps only a local path (starts with a single '/', no scheme/host/backslash/whitespace), never '/login'.
    """
    raw = (raw or "")[:512]
    if raw.startswith("/") and not raw.startswith("//") and not raw.startswith("/login") \
            and not re.search(r"[\s\\]", raw):
        return raw
    return ""


def _next_field(h: Handler) -> str:
    nxt = _safe_next(h.form.get("next") or h.query.get("next", ""))
    return f'<input type="hidden" name="next" value="{e(nxt)}">' if nxt else ""


def page_login(h: Handler, error: str = "", status: int = 200) -> None:
    if h.session and not h.session["pending_2fa"]:
        return h._redirect("/")
    msg = f'<p class="alert">{e(error)}</p>' if error else ""
    if not error and h.query.get("reset") == "done":
        msg = '<p class="alert ok">Your password was changed. Sign in with your new password.</p>'
    who = (f"{e(h.portal.cfg.issuer)} administration. Administrators only." if h.portal.admins_only() else
           f"Access to {e(h.portal.cfg.issuer)} is restricted to authorised users.")
    h._html("Sign in", f"""<section class="card narrow login">
<div class="hero">{logo.svg("brand", 72, "login")}</div>
<h1>Sign in</h1><p class="muted">{who}</p>{msg}
<form method="post" action="/login" autocomplete="on">{_next_field(h)}
<label>Username or email<input name="username" autocomplete="username" required maxlength="254" autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="128"></label>
<button class="btn primary wide">Sign in</button></form>
<p class="links"><a href="/forgot">Forgot password?</a></p></section>""", status)


def _register_failure(h: Handler, user: dict, device: dict | None, now: int) -> None:
    """Count a wrong password against the device's bucket if the browser is known, else the account's.

    An attacker without the owner's device cookie can only lock the shared "unknown client" bucket, so they
    cannot lock the owner out of the browser they actually use (OWASP device-cookie lockout).
    """
    failures = (device["failed_logins"] if device else user["failed_logins"]) + 1
    lock = now + LOCK_SECONDS if failures >= MAX_FAILURES else 0
    if device:
        h.portal.store.update_device(device["token_hash"], failed_logins=0 if lock else failures, locked_until=lock)
    else:
        h.portal.store.update_user(user["id"], failed_logins=0 if lock else failures, locked_until=lock)
    h._audit("account_locked" if lock else "login_failed",
             f"{'known-device ' if device else ''}failure {failures}", actor=user["username"])


def do_login(h: Handler) -> None:
    store, now = h.portal.store, int(time.time())
    if not h.portal.allow_attempt(h.ip):
        h._audit("login_rate_limited", actor=REDACTED_ACTOR)
        return page_login(h, "Too many attempts from your network. Wait a minute and try again.", 429)
    login = h.form.get("username", "").strip()[:254]  # username, or the account's email address
    password = h.form.get("password", "")[:auth.MAX_PASSWORD]
    user = _find_account(store, login)
    ok = auth.verify_password(password, user["password_hash"] if user else None)
    generic = "Incorrect username or password, or the account is locked or disabled."
    if user is None:
        h._audit("login_failed", "unknown user", actor=REDACTED_ACTOR)
        return page_login(h, generic, 401)
    device = h._known_device(user["id"])
    if (device["locked_until"] if device else user["locked_until"]) > now:
        h._audit("login_locked", "known device" if device else "", actor=user["username"])
        return page_login(h, generic, 401)
    if not ok:
        _register_failure(h, user, device, now)
        return page_login(h, generic, 401)
    if not user["enabled"]:
        h._audit("login_disabled", actor=user["username"])
        return page_login(h, generic, 401)
    if not h.portal.may_sign_in(user):
        h._audit("login_denied", "portal is restricted to administrators", actor=user["username"])
        return page_login(h, "This portal is restricted to administrators.", 403)
    if device:
        store.update_device(device["token_hash"], failed_logins=0, locked_until=0, last_used=now)
    else:
        store.update_user(user["id"], failed_logins=0, locked_until=0)
    nxt = _safe_next(h.form.get("next", ""))
    if user["totp_enabled"]:
        cookie = h._new_session(user, pending_2fa=True)
        h._audit("login_password_ok", "awaiting 2FA", actor=user["username"])
        loc = "/login/2fa?next=" + urllib.parse.quote(nxt, safe="/") if nxt else "/login/2fa"
        return h._redirect(loc, [cookie])
    _complete_login(h, user, device, nxt)


def _complete_login(h: Handler, user: dict, device: dict | None = None, nxt: str = "") -> None:
    cookies = [h._new_session(user, pending_2fa=False)]
    if device is None:  # mark this browser trusted for lockout scoping on future sign-ins
        cookies.append(h._device_cookie(h.portal.store.create_device(user["id"])))
    else:
        h.portal.store.update_device(device["token_hash"], last_used=int(time.time()))
    h.portal.store.update_user(user["id"], last_login_at=int(time.time()))
    h._audit("login", actor=user["username"])
    dest = "/account/password" if user["must_change_password"] else (_safe_next(nxt) or "/")
    h._redirect(dest, cookies)


def page_2fa(h: Handler, error: str = "", status: int = 200) -> None:
    msg = f'<p class="alert">{e(error)}</p>' if error else ""
    h._html("Two-factor authentication", f"""<section class="card narrow login">
<div class="hero">{logo.svg("brand", 64, "tfa")}</div><h1>Verification code</h1>
<p class="muted">Enter the 6-digit code from your authenticator app.</p>{msg}
<form method="post" action="/login/2fa">{_csrf_field(h)}{_next_field(h)}
<label>Code<input name="code" inputmode="numeric" pattern="[0-9 ]{{6,7}}" autocomplete="one-time-code" required
autofocus maxlength="7"></label><button class="btn primary wide">Verify</button></form>
<form method="post" action="/logout">{_csrf_field(h)}<button class="link">Cancel</button></form></section>""", status)


def do_2fa(h: Handler) -> None:
    store, user, now = h.portal.store, h.user, int(time.time())
    if not h.portal.allow_attempt(h.ip):
        return page_2fa(h, "Too many attempts. Wait a minute and try again.", 429)
    device = h._known_device(user["id"])
    step = auth.verify_totp(user["totp_secret"] or "", h.form.get("code", ""), user["totp_last_step"])
    if step is None:
        failures = (device["failed_logins"] if device else user["failed_logins"]) + 1
        lock = failures >= MAX_FAILURES
        if device:
            store.update_device(device["token_hash"], failed_logins=0 if lock else failures,
                                locked_until=now + LOCK_SECONDS if lock else device["locked_until"])
        else:
            store.update_user(user["id"], failed_logins=0 if lock else failures,
                              locked_until=now + LOCK_SECONDS if lock else 0)
        if lock:
            store.delete_session(h.token)
            h._audit("account_locked", f"2FA failures ({'known device' if device else 'account'})")
            return h._redirect("/login")
        h._audit("2fa_failed", f"failure {failures}")
        return page_2fa(h, "That code is not valid (or was already used).", 401)
    store.update_user(user["id"], totp_last_step=step)
    if device:
        store.update_device(device["token_hash"], failed_logins=0, locked_until=0)
    else:
        store.update_user(user["id"], failed_logins=0)
    _complete_login(h, user, device, _safe_next(h.form.get("next", "")))


# -------------------------------------------------------------------- forgot password (emailed code)

def _find_account(store: Store, login: str) -> dict | None:
    if "@" in login:
        return store.user_by_email(login) if mail.valid_email(login) else None
    return store.user_by_name(login) if USERNAME_RE.match(login) else None


def page_forgot(h: Handler, error: str = "", status: int = 200) -> None:
    msg = f'<p class="alert">{e(error)}</p>' if error else ""
    if not mail.is_configured(h.portal.settings()):
        body = ('<p class="alert info">Password recovery by email is not set up yet. Ask an administrator to '
                'reset your password.</p>')
    else:
        body = f"""<form method="post" action="/forgot">
<label>Username or email<input name="login" autocomplete="username" required maxlength="254" autofocus
value="{e(h.query.get('login', '')[:254])}"></label>
<button class="btn primary wide">Email me a code</button></form>"""
    h._html("Forgot password", f"""<section class="card narrow login">
<div class="hero">{logo.svg("brand", 64, "forgot")}</div><h1>Forgot your password?</h1>
<p class="muted">We will email a 6-digit code to the address on your account.</p>{msg}{body}
<p class="links"><a href="/login">Back to sign in</a></p></section>""", status)


def do_forgot(h: Handler) -> None:
    store, portal = h.portal.store, h.portal
    if not portal.allow_attempt(h.ip):
        h._audit("password_reset_rate_limited", actor=REDACTED_ACTOR)
        return page_forgot(h, "Too many attempts from your network. Wait a minute and try again.", 429)
    login = h.form.get("login", "").strip()[:254]
    if not login:
        return page_forgot(h, "Enter your username or email address.", 400)
    user = _find_account(store, login)
    code = f"{secrets.randbelow(10 ** 6):06d}"
    code_hash = auth.hash_password(code)  # hashed even for unknown accounts: identical timing
    now, reason = int(time.time()), ""
    if user is None:
        reason = "unknown account"
    elif not user["enabled"]:
        reason = "account disabled"
    elif not portal.may_sign_in(user):
        reason = "portal is restricted to administrators"
    elif not user["email"]:
        reason = "no email address on the account"
    elif not mail.is_configured(portal.settings()):
        reason = "email is not set up"
    else:
        recent = store.resets_since(user["id"], now - 3600)
        if recent and now - recent[0]["created_at"] < RESET_RESEND_AFTER:
            reason = "throttled: previous code sent under a minute ago"
        elif len(recent) >= RESET_MAX_PER_HOUR:
            reason = f"throttled: {RESET_MAX_PER_HOUR} codes in the last hour"
    if reason:
        h._audit("password_reset_not_sent", reason, actor=user["username"] if user else REDACTED_ACTOR)
    else:
        store.create_reset(user["id"], code_hash, RESET_TTL, h.ip)
        h._audit("password_reset_requested", f"code emailed to {mask_email(user['email'])}", actor=user["username"])
        portal.send_email_async(user["email"], mail.reset_code_message(
            portal.cfg.issuer, user["username"], code, RESET_TTL // 60, h.ip), "password reset code",
            user["username"], h.ip)
    h._redirect("/forgot/verify?" + urllib.parse.urlencode({"login": login}))


def page_forgot_verify(h: Handler, error: str = "", status: int = 200, code: str = "") -> None:
    login = (h.form.get("login") or h.query.get("login", "")).strip()[:254]
    if not login:
        return h._redirect("/forgot")
    msg = (f'<p class="alert">{e(error)}</p>' if error else
           '<p class="alert info">If an account matches, a 6-digit code is on its way to the email address on '
           f'file. It can take a minute to arrive (check spam too) and expires after {RESET_TTL // 60} minutes.</p>')
    again = urllib.parse.urlencode({"login": login})
    h._html("Reset password", f"""<section class="card narrow login">
<div class="hero">{logo.svg("brand", 64, "verify")}</div><h1>Choose a new password</h1>{msg}
<form method="post" action="/forgot/verify" autocomplete="off"><input type="hidden" name="login" value="{e(login)}">
<label>Code from the email<input name="code" inputmode="numeric" pattern="[0-9 ]{{6,7}}" autocomplete="one-time-code"
required maxlength="7" autofocus value="{e(code)}"></label>
<label>New password<input name="new" type="password" autocomplete="new-password" required minlength="{auth.MIN_PASSWORD}"
maxlength="{auth.MAX_PASSWORD}"></label>
<label>Repeat new password<input name="confirm" type="password" autocomplete="new-password" required></label>
<p class="muted small">At least {auth.MIN_PASSWORD} characters. Long passphrases are best; common passwords are refused.</p>
<button class="btn primary wide">Change password</button></form>
<p class="links"><a href="/forgot?{e(again)}">Send a new code</a> &middot; <a href="/login">Back to sign in</a></p>
</section>""", status)


def do_forgot_verify(h: Handler) -> None:
    store, portal = h.portal.store, h.portal
    if not portal.allow_attempt(h.ip):
        return page_forgot_verify(h, "Too many attempts from your network. Wait a minute and try again.", 429)
    login = h.form.get("login", "").strip()[:254]
    code = auth.digits_only(h.form.get("code", ""))
    user = _find_account(store, login)
    reset = store.active_reset(user["id"]) if user and user["enabled"] else None
    valid = auth.verify_password(code, reset["code_hash"] if reset else None) and len(code) == 6
    invalid = "That code is not valid or has expired. Use the code from the latest email, or send a new code."
    if not valid:
        if reset:
            store.reset_failed(reset["id"], RESET_MAX_ATTEMPTS)
            h._audit("password_reset_code_failed", f"attempt {reset['attempts'] + 1} of {RESET_MAX_ATTEMPTS}",
                     actor=user["username"])
        return page_forgot_verify(h, invalid, 400)
    new = h.form.get("new", "")
    if new != h.form.get("confirm", ""):
        return page_forgot_verify(h, "The new passwords do not match.", 400, code)
    problems = auth.password_problems(new, user["username"])
    if problems:
        return page_forgot_verify(h, "New password " + "; ".join(problems) + ".", 400, code)
    if not store.consume_reset(reset["id"]):  # lost a race with a parallel request: single use
        return page_forgot_verify(h, invalid, 400)
    store.update_user(user["id"], password_hash=auth.hash_password(new), must_change_password=0, failed_logins=0,
                      locked_until=0)
    store.delete_user_sessions(user["id"])
    h._audit("password_reset_by_email", "all sessions signed out", actor=user["username"])
    portal.send_email_async(user["email"], mail.password_changed_message(
        portal.cfg.issuer, user["username"], h.ip, time.strftime("%Y-%m-%d %H:%M %Z")), "password changed notice",
        user["username"], h.ip)
    h._redirect("/login?reset=done", [h._cookie("", max_age=0)] if h.token else [])


def do_logout(h: Handler) -> None:
    h.portal.store.delete_session(h.token)
    h._audit("logout")
    h._redirect("/login", [h._cookie("", max_age=0)])


def _status_card(h: Handler) -> str:
    return """<section class="card" data-live><div class="card-head"><h2>Your VPN connection</h2>
<span id="me-pill" class="pill off">Checking&hellip;</span></div>
<dl class="grid" id="me-details"><dt>Status</dt><dd id="me-state">&ndash;</dd>
<dt>Tunnel address</dt><dd id="me-address">&ndash;</dd><dt>Connected from</dt><dd id="me-endpoint">&ndash;</dd>
<dt>Connected since</dt><dd id="me-since">&ndash;</dd><dt>Encryption</dt><dd id="me-suite">&ndash;</dd>
<dt>Traffic</dt><dd id="me-traffic">&ndash;</dd></dl></section>"""


def page_dashboard(h: Handler) -> None:
    u = h.user
    issued = (f"Current profile issued {e(fmt_time(u['profile_issued_at']))} "
              f"(certificate {e((u['active_serial'] or '')[:12])}&hellip;)"
              if u["profile_issued_at"] else "You have not downloaded a profile yet.")
    tfa = ('<span class="pill on">2FA on</span>' if u["totp_enabled"]
           else '<span class="pill warn">2FA off</span> <a href="/account/2fa">Turn on</a>')
    recovery = ("" if u["email"] else '<p class="alert info small">Add a <a href="/account">recovery email</a> '
                "so you can reset a forgotten password yourself.</p>")
    h._html("Dashboard", f"""<h1 class="page">Welcome, {e(u['display_name'] or u['username'])}</h1>
<div class="cols">{_status_card(h)}
<section class="card"><h2>VPN profile</h2>
<p>Your VPN address: <code>{e(u['vpn_ip'] or 'assigned on first download')}</code></p>
<p class="muted">{issued}</p>
<form method="post" action="/profile" data-confirm="Download a new profile? Your previous profile will stop working.">
{_csrf_field(h)}<button class="btn primary">Download VPN profile</button></form>
<p class="muted small">Each download creates a fresh post-quantum key (ML-DSA-65) and invalidates the previous one.
On Windows, unzip it and run <code>python -m pqvpn tray -c client.toml</code>.</p></section>
<section class="card"><h2>Security</h2><p>Two-factor authentication: {tfa}</p>
<p>Last sign-in: {e(fmt_time(u['last_login_at']))}</p>{recovery}
<p><a href="/account">Change password, email or 2FA &rarr;</a></p></section>{_plan_card(h, u)}</div>""")


def _plan_badge(u: dict) -> str:
    plan = plans.effective_plan(u)
    return f'<span class="badge {plan}">{e(plans.PLANS[plan])}</span>'


def _dns_label(u: dict, settings: dict) -> str:
    if u["custom_dns"]:
        return f"Custom ({e(u['custom_dns'])})"
    return e(plans.describe_dns(settings, plans.effective_plan(u)))


def _plan_card(h: Handler, u: dict) -> str:
    plan = plans.effective_plan(u)
    until = (f" until {e(last_day(u['plan_expires']))}" if plan == "premium" and u["plan_expires"] else "")
    expired = ('<p class="muted small">Your Premium plan ended on '
               f'{e(last_day(u["plan_expires"]))}.</p>' if u["plan"] == "premium" and plan == "free" else "")
    upsell = ('<p class="muted small">Premium adds ad-, tracker- and malware-blocking DNS. Ask your administrator.</p>'
              if plan == "free" else "")
    return f"""<section class="card"><h2>Your plan</h2><p>{_plan_badge(u)}{until}</p>{expired}
<p>DNS through the VPN: <strong>{_dns_label(u, h.portal.settings())}</strong></p>{upsell}
<p class="muted small">Plan and DNS changes apply the next time you connect.</p></section>"""


def do_profile(h: Handler, user_id: str | None = None) -> None:
    target = h.user if user_id is None else h.portal.store.user(int(user_id))
    if target is None:
        return h._error(404, "No such user.")
    data, cert = issue_profile(h.portal.cfg, h.portal.store, h.portal.ca, target)
    h._audit("profile_issued", f"user={target['username']} serial={cert.serial_hex}")
    h._send(200, data, "application/zip",
            [("Content-Disposition", f'attachment; filename="pqvpn-{target["username"]}.zip"')])


def api_status(h: Handler) -> None:
    store = h.portal.store
    peers = store.peers()
    for p in peers:
        p["suite_label"] = describe_suite(p["suite"] or "")
    me = next((p for p in peers if p["username"].lower() == h.user["username"].lower()), None)
    hb = store.server_heartbeat()
    data = {"now": int(time.time()), "server_online": time.time() - hb < 10, "me": me}
    if h.user["role"] == "admin":
        data["peers"] = peers
    h._json(200, data)


# -------------------------------------------------------------------- account

def page_account(h: Handler, message: str = "", error: str = "") -> None:
    u = h.user
    forced = u["must_change_password"]
    note = ('<p class="alert info">Please choose a new password before continuing.</p>' if forced else "")
    msg = (f'<p class="alert ok">{e(message)}</p>' if message else "") + (
        f'<p class="alert">{e(error)}</p>' if error else "")
    tfa = ""
    if not forced:
        if u["totp_enabled"]:
            tfa = f"""<section class="card"><h2>Two-factor authentication</h2><p><span class="pill on">Enabled</span></p>
<form method="post" action="/account/2fa/disable" data-confirm="Turn off two-factor authentication?">{_csrf_field(h)}
<label>Current password<input name="password" type="password" autocomplete="current-password" required></label>
<button class="btn danger">Turn off 2FA</button></form></section>"""
        else:
            tfa = """<section class="card"><h2>Two-factor authentication</h2><p><span class="pill warn">Off</span></p>
<p>Protect your account with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy&hellip;).</p>
<p><a class="btn primary" href="/account/2fa">Set up 2FA</a></p></section>"""
    email = ""
    if not forced:
        current = (f"<code>{e(u['email'])}</code>" if u["email"] else
                   '<span class="pill warn">none</span> &ndash; you cannot reset a forgotten password yourself')
        email = f"""<section class="card"><h2>Recovery email</h2><p>Current: {current}</p>
<form method="post" action="/account/email">{_csrf_field(h)}
<label>Email address<input name="email" type="email" autocomplete="email" maxlength="254" value="{e(u['email'] or '')}"
placeholder="you@example.com"></label>
<label>Current password<input name="password" type="password" autocomplete="current-password" required></label>
<p class="muted small">Password-reset codes are sent here. Leave the address empty to remove it.</p>
<button class="btn primary">Save email</button></form></section>"""
    h._html("Account", f"""<h1 class="page">Account</h1>{note}{msg}<div class="cols">
<section class="card"><h2>Change password</h2><form method="post" action="/account/password">{_csrf_field(h)}
<label>Current password<input name="current" type="password" autocomplete="current-password" required></label>
<label>New password<input name="new" type="password" autocomplete="new-password" required minlength="{auth.MIN_PASSWORD}"
maxlength="{auth.MAX_PASSWORD}"></label>
<label>Repeat new password<input name="confirm" type="password" autocomplete="new-password" required></label>
<p class="muted small">At least {auth.MIN_PASSWORD} characters. Long passphrases are best; common passwords are refused.</p>
<button class="btn primary">Change password</button></form></section>{email}{tfa}</div>""")


def do_password(h: Handler) -> None:
    u, form = h.user, h.form
    if not h.portal.allow_attempt(h.ip):
        return page_account(h, error="Too many attempts. Please wait a minute and try again.")
    if not auth.verify_password(form.get("current", ""), u["password_hash"]):
        h._audit("password_change_failed", "wrong current password")
        return page_account(h, error="Your current password is incorrect.")
    new = form.get("new", "")
    if new != form.get("confirm", ""):
        return page_account(h, error="The new passwords do not match.")
    problems = auth.password_problems(new, u["username"])
    if auth.verify_password(new, u["password_hash"]):
        problems.append("must differ from the current password")
    if problems:
        return page_account(h, error="New password " + "; ".join(problems) + ".")
    h.portal.store.update_user(u["id"], password_hash=auth.hash_password(new), must_change_password=0)
    h.portal.store.delete_user_sessions(u["id"], keep_token=h.token)
    h._audit("password_changed")
    h.user = h.portal.store.user(u["id"])
    if u["must_change_password"]:
        return h._redirect("/")
    page_account(h, message="Password changed. Your other sessions were signed out.")


def _email_problem(store: Store, address: str, user_id: int) -> str:
    if not mail.valid_email(address):
        return "That is not a valid email address."
    other = store.user_by_email(address)
    if other and other["id"] != user_id:
        return "That email address is already used by another account."
    return ""


def do_account_email(h: Handler) -> None:
    u, store = h.user, h.portal.store
    if not h.portal.allow_attempt(h.ip):
        return page_account(h, error="Too many attempts. Please wait a minute and try again.")
    if not auth.verify_password(h.form.get("password", ""), u["password_hash"]):
        h._audit("email_change_failed", "wrong current password")
        return page_account(h, error="Your current password is incorrect; the email was not changed.")
    address = h.form.get("email", "").strip()
    if address:
        problem = _email_problem(store, address, u["id"])
        if problem:
            return page_account(h, error=problem)
    store.update_user(u["id"], email=address or None)
    h._audit("email_changed", f"{mask_email(u['email'] or '')} -> {mask_email(address)}")
    h.user = store.user(u["id"])
    page_account(h, message="Recovery email saved." if address else "Recovery email removed.")


def page_2fa_setup(h: Handler, error: str = "") -> None:
    u = h.user
    if u["totp_enabled"]:
        return h._redirect("/account")
    secret = h.session["pending_totp_secret"]
    if not secret:
        secret = auth.new_totp_secret()
        h.portal.store.set_session(h.token, pending_totp_secret=secret)
    uri = auth.otpauth_uri(secret, u["username"], h.portal.cfg.issuer)
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    msg = f'<p class="alert">{e(error)}</p>' if error else ""
    h._html("Set up 2FA", f"""<h1 class="page">Set up two-factor authentication</h1>{msg}<div class="cols">
<section class="card"><h2>1. Scan this QR code</h2><div class="qr">{QrCode(uri.encode()).svg(px=5)}</div>
<p class="muted small">Can't scan? Enter this key manually (time-based, 6 digits):</p>
<p><code class="secret">{e(grouped)}</code></p></section>
<section class="card"><h2>2. Confirm</h2><p>Enter the 6-digit code your app shows now.</p>
<form method="post" action="/account/2fa">{_csrf_field(h)}
<label>Code<input name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="7" autofocus></label>
<button class="btn primary">Turn on 2FA</button></form></section></div>""")


def do_2fa_setup(h: Handler) -> None:
    secret = h.session["pending_totp_secret"]
    if not secret:
        return h._redirect("/account/2fa")
    step = auth.verify_totp(secret, h.form.get("code", ""), 0)
    if step is None:
        return page_2fa_setup(h, "That code did not match. Check your phone's clock and try again.")
    h.portal.store.update_user(h.user["id"], totp_secret=secret, totp_enabled=1, totp_last_step=step)
    h.portal.store.set_session(h.token, pending_totp_secret=None)
    h._audit("2fa_enabled")
    h.user = h.portal.store.user(h.user["id"])
    page_account(h, message="Two-factor authentication is on. You will need your app at every sign-in.")


def do_2fa_disable(h: Handler) -> None:
    if not h.portal.allow_attempt(h.ip):
        return page_account(h, error="Too many attempts. Please wait a minute and try again.")
    if not auth.verify_password(h.form.get("password", ""), h.user["password_hash"]):
        return page_account(h, error="Incorrect password; 2FA was not turned off.")
    h.portal.store.update_user(h.user["id"], totp_enabled=0, totp_secret=None, totp_last_step=0)
    h._audit("2fa_disabled")
    h.user = h.portal.store.user(h.user["id"])
    page_account(h, message="Two-factor authentication turned off.")


# -------------------------------------------------------------------- admin

def _account_state(u: dict, now: int) -> str:
    return ('<span class="pill off">disabled</span>' if not u["enabled"] else
            '<span class="pill warn">locked</span>' if u["locked_until"] > now else
            '<span class="pill on">active</span>')


def _user_actions(h: Handler, u: dict, back: str = "") -> list[str]:
    """Per-user action buttons; ``back`` ("user" / "dashboard") is where the admin lands afterwards."""
    uid, name = u["id"], u["username"]
    ret = f'<input type="hidden" name="back" value="{e(back)}">' if back else ""

    def act(action, label, cls="", confirm=""):
        c = f' data-confirm="{e(confirm)}"' if confirm else ""
        return (f'<form method="post" action="/admin/users/{uid}/{action}"{c}>{_csrf_field(h)}{ret}'
                f'<button class="btn small {cls}">{label}</button></form>')
    actions = [] if back == "user" else [f'<a class="btn small" href="/admin/users/{uid}">Edit</a>']
    actions.append(act("disable", "Disable", "danger", f"Disable {name}? Active VPN sessions are cut.")
                   if u["enabled"] else act("enable", "Enable"))
    if u["locked_until"] > time.time():
        actions.append(act("unlock", "Unlock", "", f"Unlock {name}? (locked after too many wrong passwords)"))
    if back == "user" and uid != h.user["id"] and h.portal.store.session_count(uid):
        actions.append(act("signout", "End portal sessions", "", f"Sign {name} out of the portal everywhere?"))
    if h.portal.may_sign_in(u):
        actions.append(act("reset-password", "Reset password", "", f"Generate a new temporary password for {name}?"))
    if u["totp_enabled"]:
        actions.append(act("reset-2fa", "Reset 2FA", "", f"Remove 2FA from {name}?"))
    actions.append(act("profile", "New profile", "", f"Issue a new profile for {name}? "
                                                    "Their current profile stops working."))
    if uid != h.user["id"]:
        actions.append(act("delete", "Delete", "danger", f"Permanently delete {name}?"))
    return actions


def _notices(notice: str, error: str) -> str:
    """``notice`` is trusted markup (built by the handlers); ``error`` is escaped."""
    return (f'<div class="alert ok">{notice}</div>' if notice else "") + (
        f'<p class="alert">{e(error)}</p>' if error else "")


def _users_table(h: Handler, users: list[dict], back: str = "") -> str:
    now = int(time.time())
    connected = {p["username"].lower() for p in h.portal.store.peers()}
    rows = []
    for u in users:
        uid = u["id"]
        online = '<span class="dot on" title="connected"></span>' if u["username"].lower() in connected else \
            '<span class="dot" title="not connected"></span>'
        rows.append(f"""<tr><td>{online} <a href="/admin/users/{uid}"><strong>{e(u['username'])}</strong></a><br>
<span class="muted small">{e(u['display_name'])}{' &middot; ' if u['display_name'] and u['email'] else ''}
{e(u['email'] or '')}</span></td><td><span class="badge {e(u['role'])}">{e(u['role'])}</span></td>
<td>{_plan_badge(u)}</td><td><code>{e(u['vpn_ip'] or '-')}</code></td><td>{_account_state(u, now)}</td>
<td>{'on' if u['totp_enabled'] else '-'}</td>
<td class="small">{e(fmt_time(u['profile_issued_at']))}</td><td class="small">{e(fmt_time(u['last_login_at']))}</td>
<td><div class="acts">{''.join(_user_actions(h, u, back))}</div></td></tr>""")
    return f"""<div class="table-wrap"><table id="users-table"><thead><tr><th>User</th><th>Role</th><th>Plan</th>
<th>VPN IP</th><th>Account</th><th>2FA</th><th>Profile issued</th><th>Last sign-in</th><th>Actions</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>"""


_SEARCH_USERS = ('<input type="search" class="filter" data-filter="users-table" placeholder="Search users&hellip;" '
                 'aria-label="Search users">')
_PEERS_TABLE = """<div class="table-wrap"><table><thead><tr><th>User</th><th>Tunnel address</th><th>From</th>
<th>Since</th><th>Encryption</th><th>Received</th><th>Sent</th></tr></thead><tbody id="peers-body">
<tr><td colspan="7" class="muted">Loading&hellip;</td></tr></tbody></table></div>"""


def page_admin_dashboard(h: Handler, notice: str = "", error: str = "") -> None:
    store, me, settings = h.portal.store, h.user, h.portal.settings()
    users = store.users()
    admins = sum(u["role"] == "admin" for u in users)
    premium = sum(plans.effective_plan(u) == "premium" for u in users)
    mail_ready = mail.is_configured(settings) and mail.node_binary() and mail.nodemailer_installed()
    mail_pill = ('<span class="pill on">Ready</span>' if mail_ready else '<span class="pill warn">Not set up</span>')
    access = "Administrators only" if h.portal.admins_only() else "All users"
    activity = "".join(
        f'<tr><td class="small">{e(fmt_time(a["ts"]))}</td><td>{e(a["actor"] or "")}</td>'
        f'<td><code>{e(a["action"])}</code></td><td class="small">{e(a["detail"] or "")}</td></tr>'
        for a in store.recent_audit(8))
    issued = (f"Profile issued {e(fmt_time(me['profile_issued_at']))}." if me["profile_issued_at"]
              else "You have not downloaded a profile yet.")
    h._html("Admin dashboard", f"""<h1 class="page">Admin dashboard</h1>
<p class="muted lead">Signed in as <strong>{e(me['username'])}</strong>. Manage users, plans &amp; DNS, email,
portal access and the audit log from here.</p>{_notices(notice, error)}
<div class="tiles" data-live>
<a class="tile" href="#connected"><span class="tile-label">VPN server</span>
<span id="server-pill" class="pill off">Checking&hellip;</span></a>
<a class="tile" href="#connected"><span class="tile-label">Connected now</span>
<strong id="peer-count" class="tile-num">0</strong></a>
<a class="tile" href="/admin"><span class="tile-label">Users</span><strong class="tile-num">{len(users)}</strong>
<span class="muted small">{admins} administrator(s)</span></a>
<a class="tile" href="/admin/settings#dns"><span class="tile-label">Premium</span><strong class="tile-num">{premium}</strong>
<span class="muted small">DNS: {e(plans.describe_dns(settings, "premium").split(" (")[0])}</span></a>
<a class="tile" href="/admin/settings#email"><span class="tile-label">Password-reset email</span>{mail_pill}</a>
<a class="tile" href="/admin/settings#access"><span class="tile-label">Portal sign-in</span>
<strong>{access}</strong></a>
<a class="tile" href="/admin/settings#firebase"><span class="tile-label">Firebase mirror</span>
{_firebase_pill(h.portal.mirror.status())}</a></div>
<div class="quick"><a class="btn primary" href="/admin#add">+ Add user</a>
<a class="btn" href="/admin/settings#dns">Plans &amp; DNS</a><a class="btn" href="/admin/settings#email">Email setup</a>
<a class="btn" href="/admin/settings#access">Portal access</a><a class="btn" href="/admin/settings#firebase">Firebase</a>
<a class="btn" href="/admin/audit">Audit log</a></div>
<section class="card" id="add"><h2>Add a user</h2><form method="post" action="/admin/users" class="inline">{_csrf_field(h)}
<label>Username<input name="username" required pattern="[A-Za-z0-9][A-Za-z0-9._\\-]{{1,31}}" maxlength="32"></label>
<label>Full name<input name="display_name" maxlength="64"></label>
<label>Email<input name="email" type="email" maxlength="254" placeholder="for password recovery"></label>
<label>Plan<select name="plan"><option value="free">Free</option><option value="premium">Premium</option></select></label>
<label>Role<select name="role"><option value="user">User</option><option value="admin">Administrator</option>
</select></label><button class="btn primary">Create user</button></form>
<p class="muted small">{_create_help(h)}</p></section>
<section class="card"><div class="card-head"><h2>Users</h2>{_SEARCH_USERS}</div>
{_users_table(h, users, back="dashboard")}</section>
<section class="card" data-live id="connected"><div class="card-head"><h2>Connected now</h2></div>{_PEERS_TABLE}</section>
<div class="cols"><section class="card"><div class="card-head"><h2>Recent activity</h2>
<a class="small" href="/admin/audit">Full audit log &rarr;</a></div><div class="table-wrap"><table>
<thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Detail</th></tr></thead><tbody>{activity}</tbody></table></div>
</section>
<section class="card" data-live><div class="card-head"><h2>Your own VPN</h2>
<span id="me-pill" class="pill off">Checking&hellip;</span></div>
<dl class="grid"><dt>Tunnel address</dt><dd id="me-address">&ndash;</dd><dt>Encryption</dt><dd id="me-suite">&ndash;</dd>
<dt>Traffic</dt><dd id="me-traffic">&ndash;</dd></dl><p class="muted small">{issued}</p>
<form method="post" action="/profile" data-confirm="Download a new profile? Your previous profile will stop working.">
{_csrf_field(h)}<button class="btn">Download my VPN profile</button></form></section></div>""")


def _create_help(h: Handler) -> str:
    return ("Only administrators can sign in to this portal. A <strong>User</strong> gets VPN access only: "
            "click <em>New profile</em> to download their VPN profile and hand it over securely. An "
            "<strong>Administrator</strong> gets a one-time password to sign in here."
            if h.portal.admins_only() else
            "A one-time password is generated; the user must change it at first sign-in.")


def page_admin_user(h: Handler, user_id: str | int, notice: str = "", error: str = "",
                    form: dict | None = None) -> None:
    store, now = h.portal.store, int(time.time())
    u = store.user(int(user_id))
    if u is None:
        return h._error(404, "No such user.")
    f = form or {}  # re-show what the admin typed after a validation error
    val = lambda key, default: e(f[key] if key in f else default)  # noqa: E731
    me = u["id"] == h.user["id"]
    role = f.get("role", u["role"])
    plan = f.get("plan", u["plan"] or "free")
    role_opts = "".join(f'<option value="{k}"{" selected" if k == role else ""}>{label}</option>'
                        for k, label in (("user", "User"), ("admin", "Administrator")))
    plan_opts = "".join(f'<option value="{k}"{" selected" if k == plan else ""}>{label}</option>'
                        for k, label in plans.PLANS.items())
    lock_note = ('<p class="muted small">You cannot remove your own administrator role.</p>' if me else "")
    settings = h.portal.settings()
    online = any(p["username"].lower() == u["username"].lower() for p in store.peers())
    h._html(f"User {u['username']}", f"""<p class="crumbs"><a href="/admin">&larr; All users</a></p>
<h1 class="page">{e(u['username'])} {_plan_badge(u)}</h1>{_notices(notice, error)}<div class="cols">
<section class="card"><h2>Profile &amp; plan</h2>
<form method="post" action="/admin/users/{u['id']}/edit">{_csrf_field(h)}
<label>Full name<input name="display_name" maxlength="64" value="{val('display_name', u['display_name'])}"></label>
<label>Email <span class="hint">(password-reset codes go here)</span><input name="email" type="email" maxlength="254"
value="{val('email', u['email'] or '')}" placeholder="user@example.com"></label>
<label>Role<select name="role"{' disabled' if me else ''}>{role_opts}</select></label>{lock_note}
<div class="form-grid"><label>Plan<select name="plan">{plan_opts}</select></label>
<label>Premium until <span class="hint">(empty = no end date)</span><input name="plan_expires" type="date"
value="{val('plan_expires', last_day(u['plan_expires']))}"></label></div>
<label>DNS override <span class="hint">(optional, comma-separated; empty = the plan's DNS)</span>
<input name="custom_dns" maxlength="200" placeholder="e.g. 94.140.14.14, 94.140.15.15"
value="{val('custom_dns', u['custom_dns'] or '')}"></label>
<button class="btn primary">Save changes</button></form>
<p class="muted small">Plan and DNS changes apply the next time {e(u['username'])} connects.</p></section>
<section class="card"><h2>Status</h2><dl class="grid">
<dt>Account</dt><dd>{_account_state(u, now)}</dd>
<dt>VPN</dt><dd>{'<span class="dot on"></span>connected' if online else 'not connected'}</dd>
<dt>Plan in effect</dt><dd>{_plan_badge(u)}</dd>
<dt>DNS pushed</dt><dd>{_dns_label(u, settings)}</dd>
<dt>VPN address</dt><dd><code>{e(u['vpn_ip'] or '-')}</code></dd>
<dt>Two-factor</dt><dd>{'on' if u['totp_enabled'] else 'off'}</dd>
<dt>Profile issued</dt><dd>{e(fmt_time(u['profile_issued_at']))}</dd>
<dt>Last sign-in</dt><dd>{e(fmt_time(u['last_login_at']))}</dd>
<dt>Portal sessions</dt><dd>{store.session_count(u['id'])}</dd>
<dt>Created</dt><dd>{e(fmt_time(u['created_at']))}</dd></dl>
<h2 class="sub">Actions</h2><div class="acts">{''.join(_user_actions(h, u, back="user"))}</div></section></div>""")


def _parse_date_end(text: str) -> int:
    """'2026-12-31' -> the first second after that day (local time)."""
    t = time.strptime(text, "%Y-%m-%d")
    return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday + 1, 0, 0, 0, 0, 0, -1)))


def do_admin_edit(h: Handler, target: dict) -> None:
    store, form, me = h.portal.store, h.form, target["id"] == h.user["id"]
    redo = lambda msg: page_admin_user(h, target["id"], error=msg, form=form)  # noqa: E731
    email = form.get("email", "").strip()
    if email and (problem := _email_problem(store, email, target["id"])):
        return redo(problem)
    role = target["role"] if me else form.get("role", target["role"])
    if role not in ("user", "admin"):
        return redo("Unknown role.")
    plan = form.get("plan", "free")
    if plan not in plans.PLANS:
        return redo("Unknown plan.")
    expires = None
    if plan == "premium" and form.get("plan_expires", "").strip():
        try:
            expires = _parse_date_end(form["plan_expires"].strip())
        except (ValueError, OverflowError):
            return redo("Premium end date must be a date like 2026-12-31.")
    try:
        dns = ", ".join(plans.parse_dns(form.get("custom_dns", "")))
    except ValueError as exc:
        return redo(f"DNS override: {exc}.")
    changes = {"display_name": form.get("display_name", "").strip()[:64], "email": email or None, "role": role,
               "plan": plan, "plan_expires": expires, "custom_dns": dns or None}
    changed = {k: v for k, v in changes.items() if target[k] != v}
    if not changed:
        return page_admin_user(h, target["id"], notice="No changes.")
    store.update_user(target["id"], **changed)
    shown = {k: (mask_email(v or "") if k == "email" else last_day(v) if k == "plan_expires" else v)
             for k, v in changed.items()}
    h._audit("user_updated", f"user={target['username']} " + " ".join(f"{k}={v or '-'}" for k, v in shown.items()))
    page_admin_user(h, target["id"], notice=f"Saved: {e(', '.join(k.replace('_', ' ') for k in changed))}.")


def _temp_password_notice(username: str, password: str) -> str:
    return (f"One-time password for <strong>{e(username)}</strong>: <code class=\"secret\">{e(password)}</code>"
            "<br>Share it over a trusted channel. It is shown only once and must be changed at first sign-in.")


def do_admin_create(h: Handler) -> None:
    store, form = h.portal.store, h.form
    username = form.get("username", "").strip()
    role = form.get("role", "user")
    if not USERNAME_RE.match(username) or role not in ("user", "admin"):
        return page_admin_dashboard(h, error="Usernames are 2-32 characters: letters, digits, '.', '_' or '-'.")
    if store.user_by_name(username):
        return page_admin_dashboard(h, error=f"User {username} already exists.")
    email = form.get("email", "").strip()
    if email and (problem := _email_problem(store, email, 0)):
        return page_admin_dashboard(h, error=problem)
    plan = form.get("plan", "free") if form.get("plan") in plans.PLANS else "free"
    password = auth.generate_password()
    ip = store.allocate_ip(h.portal.cfg.subnet, h.portal.cfg.reserved_addresses)
    uid = store.create_user(username, role, password, display_name=form.get("display_name", "").strip()[:64],
                            vpn_ip=ip, must_change=True)
    store.update_user(uid, email=email or None, plan=plan)
    h._audit("user_created", f"user={username} role={role} plan={plan} ip={ip}")
    if not h.portal.may_sign_in(store.user(uid)):
        return page_admin_dashboard(h, notice=f"VPN user <strong>{e(username)}</strong> created ({e(ip)}). Click <em>New "
                                    "profile</em> next to them to download their VPN profile.")
    page_admin_dashboard(h, notice=_temp_password_notice(username, password))


def do_admin_action(h: Handler, user_id: str, action: str) -> None:
    store = h.portal.store
    target = store.user(int(user_id))
    if target is None:
        return h._error(404, "No such user.")
    name, me = target["username"], target["id"] == h.user["id"]
    back = h.form.get("back", "")

    def done(notice: str = "", error: str = "", gone: bool = False) -> None:
        if back == "user" and not gone:
            return page_admin_user(h, target["id"], notice, error)
        if back == "dashboard":
            return page_admin_dashboard(h, notice, error)
        return page_admin_dashboard(h, notice, error)

    if action == "edit":
        return do_admin_edit(h, target)
    if action in ("disable", "delete") and me:
        return done(error="You cannot disable or delete your own account.")
    if action == "disable":
        store.update_user(target["id"], enabled=0)
        store.delete_user_sessions(target["id"])
        h._audit("user_disabled", f"user={name}")
        return done(f"{e(name)} disabled; any VPN session is cut within seconds.")
    if action == "enable":
        store.update_user(target["id"], enabled=1, failed_logins=0, locked_until=0)
        store.unlock_devices(target["id"])
        h._audit("user_enabled", f"user={name}")
        return done(f"{e(name)} enabled.")
    if action == "unlock":
        store.update_user(target["id"], failed_logins=0, locked_until=0)
        store.unlock_devices(target["id"])
        h._audit("user_unlocked", f"user={name}")
        return done(f"{e(name)} unlocked.")
    if action == "signout":
        store.delete_user_sessions(target["id"], keep_token=h.token if me else None)
        h._audit("sessions_revoked", f"user={name}")
        return done(f"{e(name)} was signed out of the portal everywhere.")
    if action == "reset-password":
        password = auth.generate_password()
        store.update_user(target["id"], password_hash=auth.hash_password(password), must_change_password=1,
                          failed_logins=0, locked_until=0)
        store.delete_user_sessions(target["id"], keep_token=h.token if me else None)
        h._audit("password_reset", f"user={name}")
        return done(_temp_password_notice(name, password))
    if action == "reset-2fa":
        store.update_user(target["id"], totp_enabled=0, totp_secret=None, totp_last_step=0)
        h._audit("2fa_reset", f"user={name}")
        return done(f"2FA removed from {e(name)}.")
    if action == "profile":
        return do_profile(h, user_id)
    if action == "delete":
        store.delete_user(target["id"])
        h._audit("user_deleted", f"user={name}")
        return done(f"{e(name)} deleted; their VPN access ends within seconds.", gone=True)
    h._error(404, "Unknown action.")


# -------------------------------------------------------------------- admin settings: plans/DNS + email

def _dns_fields(plan: str, settings: dict) -> str:
    preset = settings.get(f"dns_{plan}_preset")
    opts = "".join(f'<option value="{k}"{" selected" if k == preset else ""}>{e(label)}'
                   f'{" &ndash; " + e(", ".join(ips)) if ips else ""}</option>'
                   for k, (label, ips) in plans.DNS_PRESETS.items())
    return f"""<label>{plans.PLANS[plan]} plan DNS<select name="dns_{plan}_preset">{opts}</select></label>
<label>Custom servers <span class="hint">(used when &ldquo;Custom servers&rdquo; is selected)</span>
<input name="dns_{plan}_custom" maxlength="200" placeholder="e.g. 1.1.1.2, 9.9.9.9"
value="{e(settings.get(f'dns_{plan}_custom', ''))}"></label>"""


def page_admin_settings(h: Handler, notice: str = "", error: str = "") -> None:
    settings, st = h.portal.settings(), mail.status()
    configured = mail.is_configured(settings)
    pill = ('<span class="pill on">Ready</span>' if configured and st["node"] and st["nodemailer"] else
            '<span class="pill warn">Not set up</span>')
    node = (f'<span class="pill on">Node.js {e(st["node_version"] or "")}</span>' if st["node"] else
            '<span class="pill warn">Node.js missing</span>')
    nm = (f'<span class="pill on">Nodemailer {e(st["nodemailer"])}</span>' if st["nodemailer"] else
          '<span class="pill warn">Nodemailer not installed</span>')
    sec = settings.get("smtp_security", "ssl")
    sec_opts = "".join(f'<option value="{k}"{" selected" if k == sec else ""}>{label}</option>'
                       for k, label in (("ssl", "SSL/TLS (port 465)"), ("starttls", "STARTTLS (port 587)")))
    saved_pw = "saved &ndash; leave empty to keep" if settings.get("smtp_password") else "app password"
    users = h.portal.store.users()
    premium = sum(plans.effective_plan(u) == "premium" for u in users)
    access = settings["portal_access"]
    access_opts = "".join(
        f'<label class="choice"><input type="radio" name="portal_access" value="{k}"{" checked" if k == access else ""}>'
        f'<span><strong>{title}</strong><br><span class="muted small">{desc}</span></span></label>'
        for k, title, desc in (
            ("admins", "Administrators only", "Only accounts with the Administrator role can sign in. Everyone "
             "else is VPN-only: you download their profile for them."),
            ("everyone", "All users", "Users can also sign in here to see their status and download their own "
             "VPN profile.")))
    admins = [u for u in h.portal.store.users() if u["role"] == "admin"]
    admin_list = ", ".join(e(u["username"] + (f" ({u['email']})" if u["email"] else "")) for u in admins)
    h._html("Settings", f"""<h1 class="page">Settings</h1>{_notices(notice, error)}
<section class="card" id="access"><h2>Portal access</h2>
<form method="post" action="/admin/settings/access">{_csrf_field(h)}{access_opts}
<button class="btn primary">Save access</button></form>
<p class="muted small">Administrators now: {admin_list}. To give someone access, open their page under
<a href="/admin">Users</a> and set the role to Administrator.</p></section><div class="cols">
<section class="card" id="dns"><h2>Plans &amp; DNS</h2>
<p class="muted small">{len(users) - premium} user(s) on Free, {premium} on Premium. Change a user's plan on their
page (<a href="/admin">Users</a> &rarr; Edit).</p>
<form method="post" action="/admin/settings/dns">{_csrf_field(h)}
{_dns_fields("free", settings)}<hr>{_dns_fields("premium", settings)}
<button class="btn primary">Save DNS</button></form>
<p class="muted small">The VPN server pushes these DNS servers when a client connects (a user's own DNS override wins).
Changes apply at the next connection.</p></section>
<section class="card" id="email"><div class="card-head"><h2>Email (password recovery)</h2>{pill}</div>
<p class="status-line">{node} {nm}</p>
<form method="post" action="/admin/settings/email">{_csrf_field(h)}
<div class="form-grid"><label>SMTP server<input name="smtp_host" required maxlength="253"
value="{e(settings.get('smtp_host', ''))}"></label>
<label>Security<select name="smtp_security">{sec_opts}</select></label></div>
<div class="form-grid"><label>Port<input name="smtp_port" type="number" min="1" max="65535" required
value="{e(settings.get('smtp_port', '465'))}"></label>
<label>Sender name<input name="mail_from_name" maxlength="64" placeholder="{e(h.portal.cfg.issuer)}"
value="{e(settings.get('mail_from_name', ''))}"></label></div>
<label>Email account (sends the mail)<input name="smtp_user" type="email" maxlength="254" autocomplete="off"
placeholder="you@gmail.com" value="{e(settings.get('smtp_user', ''))}"></label>
<label>App password<input name="smtp_password" type="password" maxlength="200" autocomplete="new-password"
placeholder="{saved_pw}"></label>
<button class="btn primary">Save email settings</button></form>
<form method="post" action="/admin/settings/email/test" class="inline test">{_csrf_field(h)}
<label>Send a test email to<input name="to" type="email" required maxlength="254"
value="{e(h.user['email'] or settings.get('smtp_user', ''))}"></label>
<button class="btn">Send test email</button></form>
<p class="muted small"><strong>Gmail:</strong> turn on 2-Step Verification for the account, then create an App
Password at <code>myaccount.google.com/apppasswords</code> and paste the 16-letter code above. The normal Gmail
password does not work for SMTP.</p></section></div>{_firebase_card(h)}""")


def _firebase_pill(st: dict) -> str:
    if not st["configured"]:
        return '<span class="pill warn">Not set up</span>'
    if not st["enabled"]:
        return '<span class="pill off">Paused</span>'
    if st["last_error"]:
        return '<span class="pill bad">Error</span>'
    return '<span class="pill on">Syncing</span>' if st["last_ok"] else '<span class="pill off">Starting&hellip;</span>'


def _firebase_card(h: Handler) -> str:
    st = h.portal.mirror.status()
    details = ""
    if st["configured"]:
        def act(action, label, cls="", confirm=""):
            c = f' data-confirm="{e(confirm)}"' if confirm else ""
            return (f'<form method="post" action="/admin/settings/firebase/{action}"{c}>{_csrf_field(h)}'
                    f'<button class="btn small {cls}">{label}</button></form>')
        actions = [act("sync", "Sync now"), act("pause", "Pause") if st["enabled"] else act("resume", "Resume"),
                   act("remove", "Remove key", "danger", "Stop mirroring and delete the saved key? The data already "
                                                         "in Firebase stays there.")]
        error = f'<dt>Last error</dt><dd class="bad-text">{e(st["last_error"])}</dd>' if st["last_error"] else ""
        console = f"https://console.firebase.google.com/project/{urllib.parse.quote(st['project'])}/firestore"
        details = f"""<dl class="grid"><dt>Project</dt><dd>{e(st['project'])}</dd>
<dt>Service account</dt><dd>{e(st['account'])}</dd><dt>Last sync</dt><dd>{e(fmt_time(st['last_ok']) if st['last_ok']
                                                                               else 'not yet')}</dd>
<dt>Writes since start</dt><dd>{st['writes']}</dd>{error}</dl>
<div class="acts">{''.join(actions)}</div>
<p><a href="{e(console)}" target="_blank" rel="noopener noreferrer">Open the data in the Firebase console &rarr;</a></p>"""
    label = "Replace key" if st["configured"] else "Connect Firebase"
    return f"""<section class="card" id="firebase"><div class="card-head"><h2>Firebase (Firestore mirror)</h2>
{_firebase_pill(st)}</div>
<p class="muted small">A live, read-only copy in your Firebase project: <code>users</code>, <code>connections</code>,
<code>status</code>, <code>settings</code> and <code>audit</code>. The VPN keeps using its fast local database, so it
works even when Firebase or the internet is down. Passwords, 2FA secrets, sessions, reset codes and the email app
password are <strong>never</strong> uploaded.</p>{details}
<form method="post" action="/admin/settings/firebase/connect">{_csrf_field(h)}
<label>Service-account key (JSON)<textarea name="key_json" rows="5" required spellcheck="false" autocomplete="off"
placeholder='{{"type": "service_account", "project_id": "...", "private_key": "-----BEGIN PRIVATE KEY-----..."}}'>
</textarea></label><button class="btn primary">{label}</button></form>
<p class="muted small">Get the key: Firebase console &rarr; &#9881; Project settings &rarr; <em>Service accounts</em>
&rarr; <em>Generate new private key</em>. Open the downloaded file in Notepad, copy everything and paste it here.
It is stored on this server only (file mode 0600) and never shown again.</p></section>"""


def do_admin_settings_firebase(h: Handler, action: str) -> None:
    mirror = h.portal.mirror
    if action == "connect":
        try:
            key = firebase.parse_key(h.form.get("key_json", "").strip())
        except firebase.FirebaseError as exc:
            return page_admin_settings(h, error=f"Firebase key: {exc}")
        try:
            n = mirror.connect(key)
        except firebase.FirebaseError as exc:
            saved = mirror.status()["configured"] and mirror.key() == key
            h._audit("firebase_connect_failed", f"project={key['project_id']}: {exc}")
            return page_admin_settings(h, error=(f"The key works and was saved, but the first sync failed: {exc}"
                                                 if saved else f"Firebase rejected the connection: {exc}"))
        h._audit("firebase_connected", f"project={key['project_id']} account={key['client_email']} writes={n}")
        return page_admin_settings(h, notice=f"Connected to Firebase project <strong>{e(key['project_id'])}</strong>. "
                                             f"First sync done: {n} document(s) written.")
    if not mirror.status()["configured"]:
        return page_admin_settings(h, error="Connect Firebase first.")
    if action == "sync":
        try:
            n = mirror.sync_once(force=True)
        except firebase.FirebaseError as exc:
            return page_admin_settings(h, error=f"Sync failed: {exc}")
        return page_admin_settings(h, notice=f"Synced: {n} document(s) written.")
    if action in ("pause", "resume"):
        h.portal.store.set_settings({"firebase_enabled": "1" if action == "resume" else "0"})
        h._audit(f"firebase_{'resumed' if action == 'resume' else 'paused'}")
        return page_admin_settings(h, notice="Firebase mirror resumed." if action == "resume"
                                   else "Firebase mirror paused. Nothing is sent until you resume.")
    if action == "remove":
        with mirror.lock:
            try:
                os.remove(mirror.key_path)
            except FileNotFoundError:
                pass
            h.portal.store.set_settings({"firebase_enabled": "0"})
        h._audit("firebase_key_removed")
        return page_admin_settings(h, notice="Firebase key removed; mirroring stopped. The data already in "
                                             "Firebase was left in place.")
    h._error(404, "Unknown action.")


def do_admin_settings_access(h: Handler) -> None:
    access = h.form.get("portal_access", "")
    if access not in ("admins", "everyone"):
        return page_admin_settings(h, error="Choose who can sign in.")
    h.portal.store.set_settings({"portal_access": access})
    h._audit("portal_access_changed", "administrators only" if access == "admins" else "all users")
    page_admin_settings(h, notice="Only administrators can sign in now; other users' sessions were ended."
                        if access == "admins" else "All users can sign in now.")


def do_admin_settings_dns(h: Handler) -> None:
    values = {}
    for plan in plans.PLANS:
        preset = h.form.get(f"dns_{plan}_preset", "default")
        if preset not in plans.DNS_PRESETS:
            return page_admin_settings(h, error="Unknown DNS choice.")
        try:
            custom = ", ".join(plans.parse_dns(h.form.get(f"dns_{plan}_custom", "")))
        except ValueError as exc:
            return page_admin_settings(h, error=f"{plans.PLANS[plan]} plan custom DNS: {exc}.")
        if preset == "custom" and not custom:
            return page_admin_settings(h, error=f"Enter the custom DNS servers for the {plans.PLANS[plan]} plan.")
        values[f"dns_{plan}_preset"], values[f"dns_{plan}_custom"] = preset, custom
    h.portal.store.set_settings(values)
    s = h.portal.settings()
    h._audit("dns_settings_changed", "; ".join(f"{p}={plans.describe_dns(s, p)}" for p in plans.PLANS))
    page_admin_settings(h, notice="DNS saved. Users get it the next time they connect.")


def do_admin_settings_email(h: Handler) -> None:
    f = h.form
    host = f.get("smtp_host", "").strip().lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", host):
        return page_admin_settings(h, error="SMTP server must be a host name such as smtp.gmail.com.")
    try:
        port = int(f.get("smtp_port", ""))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        return page_admin_settings(h, error="Port must be a number between 1 and 65535.")
    security = f.get("smtp_security", "ssl")
    if security not in ("ssl", "starttls"):
        return page_admin_settings(h, error="Unknown security mode.")
    user = f.get("smtp_user", "").strip()
    if user and not mail.valid_email(user):
        return page_admin_settings(h, error="The sending account must be an email address.")
    values = {"smtp_host": host, "smtp_port": str(port), "smtp_security": security, "smtp_user": user,
              "mail_from_name": f.get("mail_from_name", "").strip()[:64]}
    password = f.get("smtp_password", "")
    if re.fullmatch(r"[a-z]{4}( [a-z]{4}){3}", password.strip()):  # Google shows app passwords in groups of four
        password = password.replace(" ", "")
    if password:
        values["smtp_password"] = h.portal.vault.seal("smtp_password", password)  # encrypted at rest
    h.portal.store.set_settings(values)
    h._audit("email_settings_changed", f"{host}:{port} {security} user={mask_email(user)}"
             + (" (password updated)" if password else ""))
    page_admin_settings(h, notice="Email settings saved. Send a test email to check them.")


def do_admin_settings_email_test(h: Handler) -> None:
    to = h.form.get("to", "").strip()
    if not mail.valid_email(to):
        return page_admin_settings(h, error="Enter a valid email address for the test.")
    try:
        h.portal.send_email(to, mail.test_message(h.portal.cfg.issuer, h.user["username"]))
    except mail.MailError as exc:
        h._audit("email_failed", f"test email to {mask_email(to)}: {exc}")
        return page_admin_settings(h, error=f"Sending failed: {exc}")
    h._audit("email_sent", f"test email to {mask_email(to)}")
    page_admin_settings(h, notice=f"Test email sent to {e(to)}. Check the inbox (and the spam folder).")


def page_audit(h: Handler) -> None:
    rows = "".join(
        f"<tr><td class=\"small\">{e(fmt_time(a['ts']))}</td><td>{e(a['actor'] or '')}</td>"
        f"<td><code>{e(a['action'])}</code></td><td class=\"small\">{e(a['detail'] or '')}</td>"
        f"<td class=\"small\">{e(a['ip'] or '')}</td></tr>" for a in h.portal.store.recent_audit(300))
    h._html("Audit log", f"""<h1 class="page">Audit log</h1><section class="card"><p><input type="search"
class="filter" data-filter="audit-table" placeholder="Search events, users, IPs&hellip;" aria-label="Search the audit log">
</p><div class="table-wrap"><table id="audit-table">
<thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Detail</th><th>IP</th></tr></thead><tbody>{rows}</tbody>
</table></div></section>""")


# -------------------------------------------------------------------- static

def static_file(h: Handler, name: str) -> None:
    if name == "style.css":
        return h._send(200, STYLE.encode(), "text/css; charset=utf-8")
    if name == "app.js":
        return h._send(200, APP_JS.encode(), "text/javascript; charset=utf-8")
    if name == "logo.svg":
        return h._send(200, logo.svg("brand").encode(), "image/svg+xml")
    h._error(404, "Not found.")


def favicon(h: Handler) -> None:
    h._send(200, h.portal.favicon, "image/x-icon")


def root(h: Handler) -> None:
    # Everyone lands on the personal dashboard, admins included.  The admin console lives at /admin and is
    # reached by typing that address; it is intentionally not linked from the normal UI.
    page_dashboard(h)


ROUTES = [
    ("GET", r"/", "user", root),
    ("GET", r"/login", "public", lambda h: page_login(h)),
    ("POST", r"/login", "public", do_login),
    ("GET", r"/login/2fa", "pending", lambda h: page_2fa(h)),
    ("POST", r"/login/2fa", "pending", do_2fa),
    ("POST", r"/logout", "any", do_logout),
    ("GET", r"/forgot", "public", lambda h: page_forgot(h)),
    ("POST", r"/forgot", "public", do_forgot),
    ("GET", r"/forgot/verify", "public", lambda h: page_forgot_verify(h)),
    ("POST", r"/forgot/verify", "public", do_forgot_verify),
    ("POST", r"/profile", "user", lambda h: do_profile(h)),
    ("GET", r"/api/status", "user", api_status),
    ("GET", r"/account", "user", lambda h: page_account(h)),
    ("GET", r"/account/password", "user", lambda h: page_account(h)),
    ("POST", r"/account/password", "user", do_password),
    ("GET", r"/account/2fa", "user", lambda h: page_2fa_setup(h)),
    ("POST", r"/account/2fa", "user", do_2fa_setup),
    ("POST", r"/account/2fa/disable", "user", do_2fa_disable),
    ("POST", r"/account/email", "user", do_account_email),
    ("GET", r"/admin", "admin", lambda h: page_admin_dashboard(h)),
    ("POST", r"/admin/users", "admin", do_admin_create),
    ("GET", r"/admin/users/(?P<user_id>\d+)", "admin", lambda h, user_id: page_admin_user(h, user_id)),
    ("POST", r"/admin/users/(?P<user_id>\d+)/(?P<action>[a-z0-9-]+)", "admin", do_admin_action),
    ("GET", r"/admin/audit", "admin", page_audit),
    ("GET", r"/admin/settings", "admin", lambda h: page_admin_settings(h)),
    ("POST", r"/admin/settings/access", "admin", do_admin_settings_access),
    ("POST", r"/admin/settings/firebase/(?P<action>connect|sync|pause|resume|remove)", "admin",
     do_admin_settings_firebase),
    ("POST", r"/admin/settings/dns", "admin", do_admin_settings_dns),
    ("POST", r"/admin/settings/email", "admin", do_admin_settings_email),
    ("POST", r"/admin/settings/email/test", "admin", do_admin_settings_email_test),
    ("GET", r"/static/(?P<name>[a-z.]+)", "public", static_file),
    ("GET", r"/favicon.ico", "public", favicon),
]


# ====================================================================== assets

STYLE = """
:root{--bg:#f1f5f9;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--brand:#4f46e5;--brand2:#0891b2;
--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--radius:14px}
*{box-sizing:border-box}html,body{margin:0}
body{font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif;background:var(--bg);color:var(--ink);
min-height:100vh;display:flex;flex-direction:column}
a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
header.top{display:flex;align-items:center;gap:24px;padding:12px 28px;background:linear-gradient(90deg,#1e1b4b,#0f172a);
color:#fff;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;color:#fff;font-weight:700;font-size:19px}.brand:hover{text-decoration:none}
.brand small{font-weight:400;color:#a5b4fc;font-size:12px;letter-spacing:.04em;text-transform:uppercase;margin-left:4px}
nav{display:flex;align-items:center;gap:18px;margin-left:auto;flex-wrap:wrap}
nav a{color:#e0e7ff}nav form{margin:0}.who{color:#c7d2fe;display:flex;align-items:center;gap:6px}
main{flex:1;width:100%;max-width:1180px;margin:0 auto;padding:28px 20px}
footer{text-align:center;color:var(--muted);font-size:12px;padding:18px}
h1.page{margin:0 0 18px;font-size:26px}h1{font-size:24px;margin:0 0 6px}h2{font-size:17px;margin:0 0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin-bottom:20px;
box-shadow:0 1px 2px rgba(15,23,42,.05)}
.card.narrow{max-width:420px;margin:40px auto}.login{text-align:center}.login form{text-align:left}
.hero{display:flex;justify-content:center;margin-bottom:8px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:20px}.cols .card{margin:0}
.card-head{display:flex;justify-content:space-between;align-items:center}
label{display:block;font-weight:600;font-size:13px;margin:12px 0}
input,select,textarea{display:block;width:100%;margin-top:6px;padding:10px 12px;border:1px solid #cbd5e1;
border-radius:9px;font:inherit;background:#fff}input:focus,select:focus,textarea:focus{outline:2px solid #a5b4fc;
border-color:var(--brand)}textarea{font:12.5px/1.45 Consolas,"Cascadia Mono",monospace;resize:vertical}
form.inline{display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap}form.inline label{flex:1;min-width:160px;margin:0}
.btn{display:inline-block;border:1px solid #cbd5e1;background:#fff;color:var(--ink);padding:9px 16px;border-radius:9px;
font:inherit;font-weight:600;cursor:pointer}.btn:hover{background:#f8fafc;text-decoration:none}
.btn.primary{background:linear-gradient(180deg,#6366f1,#4f46e5);border-color:#4338ca;color:#fff}
.btn.primary:hover{background:#4338ca}.btn.danger{color:var(--bad);border-color:#fecaca}.btn.danger:hover{background:#fef2f2}
.btn.wide{width:100%;margin-top:6px;padding:11px}.btn.small{padding:5px 10px;font-size:12.5px}
button.link{background:none;border:0;color:#c7d2fe;font:inherit;cursor:pointer;padding:0}
.login button.link{color:var(--muted);margin-top:12px}
.muted{color:var(--muted)}.small{font-size:12.5px}
.alert{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px 14px;border-radius:10px}
.alert.ok{background:#f0fdf4;border-color:#bbf7d0;color:#166534}.alert.info{background:#eff6ff;border-color:#bfdbfe;color:#1e40af}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700}
.pill.on{background:#dcfce7;color:#166534}.pill.bad{background:#fee2e2;color:#991b1b}
.bad-text{color:var(--bad);font-weight:600}.pill.off{background:#e2e8f0;color:#475569}.pill.warn{background:#fef3c7;color:#92400e}
.badge{font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 7px;border-radius:6px;background:#e0e7ff;color:#3730a3}
.badge.admin{background:#fae8ff;color:#86198f}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#cbd5e1;margin-right:4px}.dot.on{background:var(--ok);
box-shadow:0 0 0 3px #bbf7d0}
dl.grid{display:grid;grid-template-columns:140px 1fr;gap:6px 12px;margin:0}dt{color:var(--muted)}dd{margin:0;font-weight:600}
code{font-family:Consolas,"Cascadia Mono",monospace;background:#f1f5f9;padding:1px 6px;border-radius:6px}
code.secret{font-size:15px;letter-spacing:.06em;background:#eef2ff;padding:4px 8px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 10px;
border-bottom:1px solid var(--line);vertical-align:middle}th{font-size:12px;color:var(--muted);text-transform:uppercase;
letter-spacing:.04em}.acts{display:flex;gap:6px;flex-wrap:wrap}.acts form{margin:0}dd{overflow-wrap:anywhere}
.qr{display:flex;justify-content:center;padding:8px}.qr svg{max-width:100%;height:auto;border-radius:8px}
.badge.premium{background:linear-gradient(90deg,#fde68a,#fbbf24);color:#78350f}.badge.free{background:#e2e8f0;color:#334155}
h1.page .badge{font-size:12px;vertical-align:middle;margin-left:6px}
.links{margin:16px 0 0;font-size:13.5px}.login .links{text-align:center}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:0 14px}
.hint{font-weight:400;color:var(--muted);font-size:12px}.crumbs{margin:0 0 6px;font-size:13.5px}
h2.sub{font-size:14px;margin:18px 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
hr{border:0;border-top:1px solid var(--line);margin:16px 0 4px}.status-line{display:flex;gap:6px;flex-wrap:wrap}
form.test{margin-top:18px;padding-top:14px;border-top:1px solid var(--line)}
input:disabled,select:disabled{background:#f8fafc;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px;display:flex;
flex-direction:column;gap:6px;color:var(--ink);box-shadow:0 1px 2px rgba(15,23,42,.05)}
a.tile:hover{text-decoration:none;border-color:#a5b4fc}.tile .pill{align-self:flex-start}
.tile-label{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:700}
.tile-num{font-size:28px;line-height:1.1}.quick{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 20px}
.lead{margin:-8px 0 18px}main>.alert{margin:0 0 16px}.cols+.card{margin-top:20px}input.filter{max-width:300px;margin:0}tr[hidden]{display:none}
label.choice{display:flex;gap:10px;align-items:flex-start;font-weight:400;font-size:14px;padding:10px 12px;
border:1px solid var(--line);border-radius:10px;cursor:pointer}label.choice input{width:auto;margin:3px 0 0}
"""

APP_JS = r"""
(() => {
  "use strict";
  document.querySelectorAll("form[data-confirm]").forEach(f =>
    f.addEventListener("submit", ev => { if (!window.confirm(f.dataset.confirm)) ev.preventDefault(); }));
  document.querySelectorAll("input[data-filter]").forEach(inp => inp.addEventListener("input", () => {
    const q = inp.value.trim().toLowerCase();
    document.querySelectorAll("#" + inp.dataset.filter + " tbody tr").forEach(tr => {
      tr.hidden = q !== "" && !tr.textContent.toLowerCase().includes(q); });
  }));
  if (!document.querySelector("[data-live]")) return;
  const $ = id => document.getElementById(id);
  const bytes = n => { n = Number(n || 0); const u = ["B","KB","MB","GB","TB"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : n.toFixed(0)) + " " + u[i]; };
  const when = t => t ? new Date(t * 1000).toLocaleString() : "–";
  const set = (id, text) => { const el = $(id); if (el) el.textContent = text; };
  const pill = (id, on, yes, no, warn) => { const el = $(id); if (!el) return;
    el.textContent = on ? yes : no; el.className = "pill " + (on ? "on" : (warn ? "warn" : "off")); };
  function render(d) {
    pill("server-pill", d.server_online, "Server online", "Server offline", true);
    const me = d.me;
    pill("me-pill", !!me, "Connected", "Not connected");
    set("me-state", me ? "Connected through the post-quantum tunnel" : "Not connected");
    set("me-address", me ? me.address : "–");
    set("me-endpoint", me ? me.endpoint : "–");
    set("me-since", me ? when(me.connected_since) : "–");
    set("me-suite", me ? me.suite_label + " · identity " + me.key_alg : "–");
    set("me-traffic", me ? bytes(me.rx_bytes) + " sent, " + bytes(me.tx_bytes) + " received" : "–");
    if (d.peers) {
      set("peer-count", String(d.peers.length));
      const body = $("peers-body");
      if (body) {
        const rows = d.peers.map(p => {
          const tr = document.createElement("tr");
          [p.username, p.address, p.endpoint, when(p.connected_since), p.suite_label, bytes(p.rx_bytes), bytes(p.tx_bytes)]
            .forEach(v => { const td = document.createElement("td"); td.textContent = v; tr.appendChild(td); });
          return tr;
        });
        if (!rows.length) { const tr = document.createElement("tr"); const td = document.createElement("td");
          td.colSpan = 7; td.className = "muted"; td.textContent = "Nobody is connected."; tr.appendChild(td); rows.push(tr); }
        body.replaceChildren(...rows);
      }
    }
  }
  async function refresh() {
    try {
      const r = await fetch("/api/status", {credentials: "same-origin", cache: "no-store"});
      if (r.status === 401) { window.location.href = "/login"; return; }
      if (r.ok) render(await r.json());
    } catch (err) { /* transient network error: try again next tick */ }
  }
  refresh();
  setInterval(refresh, 3000);
})();
"""


def run_portal(cfg: PortalConfig) -> None:
    portal = Portal(cfg)
    try:
        portal.ca  # fail fast if the CA cannot be loaded
    except Exception as exc:
        raise SystemExit(f"cannot load CA for profile issuance: {exc}")
    urls = portal.start()
    log.info("pqvpn portal listening on %s", ", ".join(urls))
    if not portal.tls:
        log.info("plain HTTP is only served on loopback / VPN-tunnel addresses (configure TLS for anything else)")
    stop = threading.Event()
    threading.Thread(target=portal.mirror.run, args=(stop,), name="firebase-mirror", daemon=True).start()
    try:
        while not stop.wait(600):
            portal.store.purge_sessions(cfg.session_idle, cfg.session_max)
            portal.store.purge_resets(24 * 3600)
            portal.store.purge_devices(DEVICE_TTL)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        portal.stop()
