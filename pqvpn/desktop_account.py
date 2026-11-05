"""Desktop side of Free-with-ads and Pro: this PC registers itself with the portal (no account needed for Free)
and keeps a normal client profile that ``run_client`` uses unchanged.

Files in the data directory (default ``%LOCALAPPDATA%\\pqvpn\\device``):

  client.toml, device.crt, ca.crt   the public profile (account_client.write_profile)
  device.key    the ML-DSA private key as PKCS#8, encrypted by OpenSSL (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC)
                with a random 256-bit passphrase
  psk.key       the server's pre-shared key (base64), the same value every enrolled device receives
  account.json  the portal address and certificate pin, plus the key passphrase and the device's API token,
                both sealed with Windows DPAPI (CryptProtectData, current user).  On other systems they are
                stored unsealed in a 0600 file -- the same protection as a profile ZIP's key file.

At connect time ``load_config`` unseals the passphrase into ``cfg.key_passphrase``, so the key is decrypted
only inside OpenSSL in the VPN process.  The Windows app runs elevated (UAC) as the same user, so DPAPI works
in both the normal and the elevated process.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import shutil
import sys
import tempfile

from .account_client import DEFAULT_KEY_ALG, PortalClient, PortalError, new_device_key, write_profile

ACCOUNT_FILE = "account.json"


def default_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "pqvpn", "device")


# ------------------------------------------------------------------ DPAPI (Windows) sealing

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # 0x1 = CRYPTPROTECT_UI_FORBIDDEN: never show a prompt.
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        raise OSError(f"Windows DPAPI failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def seal(value: bytes) -> str:
    if sys.platform == "win32":
        return "dpapi:" + base64.b64encode(_dpapi(value, True)).decode()
    return "plain:" + base64.b64encode(value).decode()


def unseal(text: str) -> bytes:
    kind, _, data = text.partition(":")
    raw = base64.b64decode(data)
    if kind == "dpapi":
        return _dpapi(raw, False)
    if kind == "plain":
        return raw
    raise ValueError("unknown sealing")


def _write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


# ------------------------------------------------------------------ the device

class DesktopAccount:
    def __init__(self, data_dir: str | None = None):
        self.dir = os.path.abspath(data_dir or default_dir())

    @property
    def config_path(self) -> str:
        return os.path.join(self.dir, "client.toml")

    def exists(self) -> bool:
        return os.path.isfile(os.path.join(self.dir, ACCOUNT_FILE)) and os.path.isfile(self.config_path)

    def _state(self) -> dict:
        with open(os.path.join(self.dir, ACCOUNT_FILE), encoding="utf-8") as f:
            return json.load(f)

    def portal(self) -> PortalClient:
        s = self._state()
        return PortalClient(s["portal_url"], s.get("pin", ""), bool(s.get("allow_http")))

    def token(self) -> str:
        return unseal(self._state()["token"]).decode("ascii")

    def load_config(self):
        """The client profile with the key passphrase unsealed (for run_client)."""
        from .config import load_client
        cfg = load_client(self.config_path)
        cfg.key_passphrase = unseal(self._state()["key_passphrase"])
        return cfg

    # -------------------------------------------------------------- enrollment
    @classmethod
    def enroll(cls, portal_url: str, pin: str = "", allow_http: bool = False,
               data_dir: str | None = None) -> "DesktopAccount":
        """Register this PC (Free plan, no account) and install its profile."""
        acct = cls(data_dir)
        client = PortalClient(portal_url, pin, allow_http)  # validates the address and pin first
        key_pem, public_b64 = new_device_key(DEFAULT_KEY_ALG)
        out = client.call("POST", "/api/v1/enroll", {"platform": "windows", "key_alg": DEFAULT_KEY_ALG,
                                                     "public_key": public_b64})
        token = out.get("token")
        if not isinstance(token, str) or not isinstance(out.get("profile"), dict):
            raise PortalError(0, "bad_profile", "the server's answer is incomplete")
        state = {"portal_url": portal_url, "pin": pin, "allow_http": bool(allow_http), "token": seal(token.encode())}
        acct._install(out["profile"], key_pem, state)
        return acct

    def renew(self) -> None:
        """A fresh key and certificate before the old certificate expires."""
        key_pem, public_b64 = new_device_key(DEFAULT_KEY_ALG)
        out = self.call("POST", "/api/v1/renew", {"key_alg": DEFAULT_KEY_ALG, "public_key": public_b64})
        self._install(out["profile"], key_pem, self._state())

    def _install(self, profile: dict, key_pem: str, state: dict) -> None:
        """Write everything into a fresh directory, check it, then swap it in (never a half-written profile)."""
        from .crypto import ossl
        parent = os.path.dirname(self.dir)
        os.makedirs(parent, exist_ok=True)
        staging = tempfile.mkdtemp(prefix="device-", dir=parent)
        try:
            # Text, not raw bytes: OpenSSL takes the passphrase as a C string, so a 0 byte would cut it short.
            passphrase = secrets.token_urlsafe(32).encode("ascii")
            key = ossl.private_from_pem(key_pem.encode("ascii"))
            _write_private(os.path.join(staging, "device.key"), ossl.private_to_pem(key, passphrase))
            psk = str(profile.get("psk") or "")
            if psk:
                _write_private(os.path.join(staging, "psk.key"), psk.encode("ascii") + b"\n")
            obfs = str(profile.get("obfuscation_key") or "")
            if obfs:  # stealth key (semi-public, but kept 0600 like the rest of the device folder)
                _write_private(os.path.join(staging, "obfs.key"), obfs.encode("ascii") + b"\n")
            write_profile(profile, key_pem, staging, key_file="device.key", psk_file="psk.key" if psk else None,
                          obfs_file="obfs.key" if obfs else None)
            state = {**state, "key_passphrase": seal(passphrase), "subject": profile.get("subject", "")}
            _write_private(os.path.join(staging, ACCOUNT_FILE), json.dumps(state, indent=2).encode())
            old = self.dir + ".old"
            shutil.rmtree(old, ignore_errors=True)
            if os.path.isdir(self.dir):
                os.replace(self.dir, old)
            os.replace(staging, self.dir)
            shutil.rmtree(old, ignore_errors=True)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    # -------------------------------------------------------------- API
    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        return self.portal().call(method, path, body, token=self.token())

    def me(self) -> dict:
        return self.call("GET", "/api/v1/me")

    def link(self, path: str, body: dict | None = None) -> str:
        """A one-time browser link from the portal: "/api/v1/checkout" (body {"period": ...}) or "/api/v1/manage"."""
        url = self.call("POST", path, body or {}).get("url", "")
        if not url.startswith(("https://", "http://")):
            raise PortalError(0, "bad_response", "the server did not return a link")
        return url

    def web_reward_url(self) -> str:
        """Start one web-ad view (Windows Free time); the page grants the time after the minimum viewing time."""
        out = self.call("POST", "/api/v1/reward/start", {"kind": "web"})
        url = out.get("url", "")
        if not url.startswith(("https://", "http://")):
            raise PortalError(0, "bad_response", "the server did not return an ad page")
        return url


def account_for_config(config_path: str) -> DesktopAccount | None:
    """The enrolled device whose profile this is, or None for a profile imported from a portal ZIP."""
    acct = DesktopAccount(os.path.dirname(os.path.abspath(config_path)))
    return acct if acct.exists() else None


def load_config(config_path: str):
    """load_client() for both kinds of profile: an enrolled device's key passphrase is unsealed here."""
    acct = account_for_config(config_path)
    if acct is not None:
        return acct.load_config()
    from .config import load_client
    return load_client(config_path)
