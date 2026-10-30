"""The three ShieldsVPN products on the admin console: the website, the browser extension and the apps.

Settings (all optional, empty by default): the public website's address and the store pages of the browser
extension, shown on the admin pages.  ``check_pages`` lets an administrator see whether the website's legal pages
answer; it only speaks HTTPS to a public address, follows no redirects and reads no body (OWASP SSRF prevention).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from typing import Callable

DEFAULT_SETTINGS = {
    "website_url": "",            # e.g. https://shieldsvpn.vercel.app/
    "extension_chrome_url": "",   # Chrome Web Store page (also used by Brave and Opera)
    "extension_edge_url": "",     # Microsoft Edge Add-ons page
    "extension_firefox_url": "",  # Firefox Add-ons page
}

# The website's pages an administrator cares about (public/ in this repository).
WEBSITE_PAGES = (("Home", "/"), ("Privacy policy", "/privacy.html"), ("User agreement", "/terms.html"),
                 ("Delete account", "/delete-account.html"))

# Store pages are only accepted on the stores' own hosts.
STORES = {
    "extension_chrome_url": ("Chrome Web Store", ("chromewebstore.google.com", "chrome.google.com")),
    "extension_edge_url": ("Microsoft Edge Add-ons", ("microsoftedge.microsoft.com",)),
    "extension_firefox_url": ("Firefox Add-ons", ("addons.mozilla.org",)),
}

_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/%+-]*$")
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
MAX_URL = 300


def _is_ip(host: str) -> bool:
    """An IP address written as a host (also the all-digits forms the URL parser keeps as text)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return host.rsplit(".", 1)[-1].isdigit()


def clean_url(value: str, hosts: tuple[str, ...] = ()) -> str:
    """An https:// address with a public-looking host name (optionally one of ``hosts``), or "" for empty.

    Raises ValueError with a message for people.  Returned without query or fragment.
    """
    value = value.strip()
    if not value:
        return ""
    if len(value) > MAX_URL or any(c.isspace() for c in value):
        raise ValueError("the address is too long or contains spaces")
    u = urllib.parse.urlsplit(value)
    host = (u.hostname or "").lower()
    if u.scheme != "https" or not _HOST_RE.match(host) or _is_ip(host) or u.username or u.password:
        raise ValueError("use an https:// address with a host name, e.g. https://example.com/")
    if hosts and host not in hosts:
        raise ValueError(f"the address must be on {' or '.join(hosts)}")
    if not _PATH_RE.match(u.path or "/"):
        raise ValueError("the address contains characters that are not allowed")
    port = f":{u.port}" if u.port else ""
    return urllib.parse.urlunsplit(("https", host + port, u.path or "/", "", ""))


def page_url(base: str, path: str) -> str:
    """``path`` on the website ``base`` (both already cleaned)."""
    return urllib.parse.urljoin(base, path.lstrip("/")) if path != "/" else base


def _public_ip(host: str, port: int) -> str:
    """Resolve once and refuse internal addresses (no SSRF into the server's own network)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for *_, addr in infos:
        ip = addr[0].split("%")[0]
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("the address points into a private network")
    return infos[0][4][0]


def _fetch_status(url: str, timeout: float) -> int:
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname or "", u.port or 443
    ip = _public_ip(host, port)

    class Pinned(http.client.HTTPSConnection):  # connect to the checked address, verify TLS for the host name
        def connect(self):
            sock = socket.create_connection((ip, port), timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=host)

    conn = Pinned(host, port, timeout=timeout, context=ssl.create_default_context())
    try:
        conn.request("HEAD", u.path or "/", headers={"User-Agent": "ShieldsVPN-admin-check/1"})
        return conn.getresponse().status
    finally:
        conn.close()


def check_pages(base: str, pages=WEBSITE_PAGES, timeout: float = 6.0,
                fetch: Callable[[str, float], int] = _fetch_status) -> list[dict]:
    """HEAD each page of the website; returns [{name, url, status, ms, ok, error}] (never raises)."""
    out = []
    for name, path in pages:
        url = page_url(base, path)
        start = time.monotonic()
        try:
            status, error = fetch(url, timeout), ""
        except (OSError, ValueError, http.client.HTTPException, ssl.SSLError) as exc:
            status, error = 0, str(exc)[:120] or type(exc).__name__
        out.append({"name": name, "url": url, "status": status, "ok": 200 <= status < 300, "error": error,
                    "ms": int((time.monotonic() - start) * 1000)})
    return out


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def extension_info(root: str | None = None) -> dict | None:
    """The browser extension's manifest (browser-extension/manifest.json), or None when it is not on this server."""
    path = os.path.join(root or project_root(), "browser-extension", "manifest.json")
    try:
        with open(path, encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(m, dict):
        return None
    perms = m.get("permissions") if isinstance(m.get("permissions"), list) else []
    return {"name": str(m.get("name", "")), "version": str(m.get("version", "")),
            "manifest_version": m.get("manifest_version"), "description": str(m.get("description", "")),
            "permissions": [str(p) for p in perms], "min_chrome": str(m.get("minimum_chrome_version", ""))}
