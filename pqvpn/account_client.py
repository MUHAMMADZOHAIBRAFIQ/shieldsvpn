"""Client side of the portal's app API (pqvpn/portal/api.py), shared by the Android and Windows apps.

Standard library only, so it runs inside the Android APK (Chaquopy) and on a bare Windows Python.

TLS policy for reaching the portal:

  * **Pinned** (``pin`` = SHA-256 of the portal's DER certificate, hex): the connection is used only if the server
    presents exactly that certificate.  This is for a portal with a self-signed certificate reached through a
    tunnel service such as playit.gg, where no public CA can vouch for the host name (certificate pinning,
    OWASP MASVS-NETWORK-2).  The check runs right after the TLS handshake, before any request byte is sent.
  * **Not pinned**: normal certificate-chain and host-name verification against the system CAs (a portal with a
    real domain and, e.g., a Let's Encrypt certificate).
  * Plain ``http://`` only when the caller explicitly allows it (local testing, the Android emulator).

Device keys: ``new_device_key`` generates the ML-DSA key pair through OpenSSL (crypto/ossl.py); only the public
key is ever sent to the portal.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import socket
import ssl
import urllib.parse

DEFAULT_KEY_ALG = "ML-DSA-65"
MAX_RESPONSE = 1 << 20


class PortalError(Exception):
    """A failed API call.  ``code`` is the portal's machine-readable error ("network" when it was not reached)."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def cert_pin(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def pem_to_der(pem: str) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem)


class PortalClient:
    def __init__(self, base_url: str, pin: str = "", allow_http: bool = False, timeout: float = 20):
        u = urllib.parse.urlsplit(base_url.strip())
        if u.scheme not in ("https", "http") or not u.hostname:
            raise ValueError("the portal address must be an https:// URL")
        if u.scheme == "http" and not allow_http:
            raise ValueError("the portal address must use https://")
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname, u.port or (443 if self.https else 80)
        self.base_path = u.path.rstrip("/")
        self.pin = pin.strip().lower().replace(":", "")
        if self.pin and len(self.pin) != 64:
            raise ValueError("the certificate pin must be a SHA-256 fingerprint (64 hex digits)")
        self.timeout = timeout

    def _connection(self) -> http.client.HTTPConnection:
        if not self.https:
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        if self.pin:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # trust comes from the pin, checked below before anything is sent
        else:
            ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        conn.connect()
        if self.pin:
            der = conn.sock.getpeercert(binary_form=True) or b""
            if not hmac.compare_digest(cert_pin(der), self.pin):
                conn.close()
                raise PortalError(0, "pin_mismatch", "the portal's certificate is not the expected one "
                                                     "(possible interception); not connecting")
        return conn

    def call(self, method: str, path: str, body: dict | None = None, token: str | None = None) -> dict:
        headers = {"Accept": "application/json", "User-Agent": "ShieldsVPN-app"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            conn = self._connection()
            try:
                conn.request(method, self.base_path + path, body=data, headers=headers)
                r = conn.getresponse()
                raw = r.read(MAX_RESPONSE + 1)
                status = r.status
            finally:
                conn.close()
        except PortalError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as exc:
            raise PortalError(0, "network", f"cannot reach the ShieldsVPN server ({exc.__class__.__name__})") from None
        if len(raw) > MAX_RESPONSE:
            raise PortalError(status, "bad_response", "the server's answer is too large")
        try:
            out = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, ValueError):
            out = None
        if not isinstance(out, dict):
            raise PortalError(status, "bad_response", f"unexpected answer from the server (HTTP {status})")
        if not 200 <= status < 300:
            raise PortalError(status, str(out.get("error", "error")), str(out.get("message", f"HTTP {status}")))
        return out


# ------------------------------------------------------------------ device keys and profiles

def new_device_key(alg_name: str = DEFAULT_KEY_ALG) -> tuple[str, str]:
    """(private key PEM, public key base64).  The private key must be stored encrypted by the caller."""
    from .crypto import ossl
    from .crypto.suites import sig_alg_by_name
    alg = sig_alg_by_name(alg_name)
    key = alg.generate()
    return ossl.private_to_pem(key).decode("ascii"), base64.b64encode(alg.public_bytes(key)).decode("ascii")


def public_from_private(key_pem: str, alg_name: str = DEFAULT_KEY_ALG) -> str:
    from .crypto import ossl
    from .crypto.suites import sig_alg_by_name
    return base64.b64encode(sig_alg_by_name(alg_name).public_bytes(ossl.private_from_pem(key_pem.encode()))).decode()


CLIENT_TOML = """\
# ShieldsVPN device profile ({subject}) -- written by the app from the portal's enrollment answer.
[client]
server = "{server}"
server_name = "{server_name}"
certificate = "device.crt"
private_key = "{key_file}"
ca = ["ca.crt"]
portal_url = "{portal_url}"

[tunnel]
interface = "pqvpn0"
mtu = 1420
full_tunnel = {full_tunnel}
routes = []
use_server_dns = true
persistent_keepalive = 25

[crypto]
suites = [{suites}]
peer_signature_algorithms = ["ML-DSA-65", "ML-DSA-87"]
ca_signature_algorithms = ["{ca_alg}"]
rekey_interval = 120
{psk_line}"""

_TOML_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/[]@+% ")


def _toml_str(value, what: str) -> str:
    s = str(value)
    if len(s) > 512 or not set(s) <= _TOML_SAFE:
        raise PortalError(0, "bad_profile", f"the server sent an invalid {what}")
    return s


def write_profile(profile: dict, key_pem: str, dest_dir: str, key_file: str = "device.key",
                  psk_file: str | None = None) -> dict:
    """Write a client profile (the same layout as a portal ZIP) from an enrollment answer and check it.

    ``key_file``/``psk_file`` name where the caller keeps the private key and PSK: Android keeps both sealed in
    the Keystore and passes key_file only for the config line; Windows writes them next to client.toml.
    Returns the parsed ClientConfig.  Raises PortalError if the answer does not fit the key or the CA.
    """
    from . import pki
    from .config import load_client
    from .crypto import ossl

    suites = profile.get("suites") or []
    if not isinstance(suites, list) or not suites:
        raise PortalError(0, "bad_profile", "the server sent no cipher suites")
    text = CLIENT_TOML.format(
        subject=_toml_str(profile.get("subject", ""), "device name"),
        server=_toml_str(profile.get("server", ""), "server address"),
        server_name=_toml_str(profile.get("server_name", ""), "server name"),
        key_file=key_file, portal_url=_toml_str(profile.get("portal_url", ""), "portal address"),
        full_tunnel="true" if profile.get("full_tunnel") else "false",
        suites=", ".join(f'"{_toml_str(s, "suite")}"' for s in suites),
        ca_alg=_toml_str(profile.get("ca_algorithm", ""), "CA algorithm"),
        psk_line=f'psk_file = "{psk_file}"\n' if psk_file else "")
    os.makedirs(dest_dir, exist_ok=True)
    for name, content in (("client.toml", text), ("device.crt", profile.get("certificate", "")),
                          ("ca.crt", profile.get("ca", ""))):
        with open(os.path.join(dest_dir, name), "w", encoding="ascii", newline="\n") as f:
            f.write(content)
    try:
        cfg = load_client(os.path.join(dest_dir, "client.toml"))  # reads the PSK file if named, never the key
        cert = pki.Certificate.load(cfg.certificate)
        pki.Identity(cert, ossl.private_from_pem(key_pem.encode("ascii")))  # the certificate is for our key
        pki.TrustStore.load(cfg.ca, peer_algs=cfg.crypto.peer_sig_algs, ca_algs=cfg.crypto.ca_sig_algs) \
            .verify(cert, pki.ROLE_CLIENT)
        if cert.subject != profile.get("subject"):
            raise pki.CertError("certificate subject does not match the device")
    except PortalError:
        raise
    except Exception as exc:  # noqa: BLE001 -- ConfigError, CertError, OpenSSLError, OSError
        raise PortalError(0, "bad_profile", f"the server's answer is not a usable profile: {exc}") from None
    return cfg
