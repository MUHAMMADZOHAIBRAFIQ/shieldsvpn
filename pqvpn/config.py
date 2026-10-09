"""TOML configuration (stdlib tomllib) with strict validation.

Relative paths are resolved against the directory of the config file.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass, field

from .crypto.suites import (DEFAULT_CA_SIG_ALGS, DEFAULT_PEER_SIG_ALGS, DEFAULT_SUITES, Suite,
                            sig_alg_by_name, suite_by_name)

_IFNAME = re.compile(r"^[A-Za-z0-9_\-]{1,15}$")


class ConfigError(Exception):
    pass


@dataclass
class CryptoConfig:
    suites: tuple[Suite, ...]
    peer_sig_algs: tuple[str, ...]
    ca_sig_algs: tuple[str, ...]
    psk: bytes | None
    rekey_interval: int


@dataclass
class ServerConfig:
    listen_host: str
    listen_port: int
    certificate: str
    private_key: str
    key_passphrase: bytes | None
    ca: list[str]
    interface: str
    mtu: int
    addresses: list[str]
    dns: list[str]
    push_routes: list[str]
    nat_interface: str
    crypto: CryptoConfig
    revoked: set[str]
    max_peers: int
    cookie_threshold: int
    always_require_cookie: bool
    handshake_rate: float
    portal_database: str = ""
    portal_url: str = ""


@dataclass
class ClientConfig:
    server_host: str
    server_port: int
    server_name: str
    certificate: str
    private_key: str
    key_passphrase: bytes | None
    ca: list[str]
    interface: str
    mtu: int
    full_tunnel: bool
    routes: list[str]
    use_server_dns: bool
    dns: list[str]
    persistent_keepalive: int
    crypto: CryptoConfig
    revoked: set[str] = field(default_factory=set)
    portal_url: str = ""


@dataclass
class PortalConfig:
    listen: list[tuple[str, int]]
    public_url: str
    database: str
    tls_certificate: str | None
    tls_private_key: str | None
    allow_insecure_http: bool
    issuer: str
    require_2fa_for_admins: bool
    session_idle: int
    session_max: int
    server_name: str
    endpoint: str
    subnet: str
    reserved_addresses: set[str]
    ca_certificate: str
    ca_private_key: str
    ca_passphrase: bytes | None
    psk_file: str | None
    client_algorithm: str
    certificate_days: float
    suites: list[str]
    vpn_portal_url: str
    allowed_hosts: list[str] = field(default_factory=list)  # extra Host names (besides IPs/localhost/URLs)
    allow_internal_smtp: bool = False  # let the SMTP server be a loopback/private address (local relay)


_REQUIRED = object()


class _Section:
    def __init__(self, data: dict, name: str, base: str):
        self.data, self.name, self.base = data, name, base
        self.used: set[str] = set()

    def _get(self, key, default, types):
        self.used.add(key)
        if key not in self.data:
            if default is _REQUIRED:
                raise ConfigError(f"[{self.name}] {key} is required")
            return default
        v = self.data[key]
        if not isinstance(v, types) or (isinstance(v, bool) and bool not in _as_tuple(types)):
            raise ConfigError(f"[{self.name}] {key} has wrong type")
        return v

    def str(self, key, default=None):
        return self._get(key, default, str)

    def int(self, key, default=None, lo=None, hi=None):
        v = self._get(key, default, int)
        if v is not None and ((lo is not None and v < lo) or (hi is not None and v > hi)):
            raise ConfigError(f"[{self.name}] {key} must be in [{lo}, {hi}]")
        return v

    def bool(self, key, default=False):
        return self._get(key, default, bool)

    def strs(self, key, default=()):
        v = self._get(key, list(default), list)
        if not all(isinstance(x, str) for x in v):
            raise ConfigError(f"[{self.name}] {key} must be a list of strings")
        return list(v)

    def path(self, key, default=None):
        v = self.str(key, default)
        return None if v is None else os.path.normpath(os.path.join(self.base, os.path.expanduser(v)))

    def paths(self, key):
        return [os.path.normpath(os.path.join(self.base, os.path.expanduser(p))) for p in self.strs(key)]

    def check_unknown(self):
        extra = set(self.data) - self.used
        if extra:
            raise ConfigError(f"[{self.name}] unknown key(s): {', '.join(sorted(extra))}")


def _as_tuple(t):
    return t if isinstance(t, tuple) else (t,)


def _hostport(text: str, what: str) -> tuple[str, int]:
    m = re.match(r"^\[(.+)\]:(\d+)$", text) or re.match(r"^([^:]+):(\d+)$", text)
    if not m:
        raise ConfigError(f"{what} must be host:port or [v6]:port, got {text!r}")
    port = int(m.group(2))
    if not 1 <= port <= 65535:
        raise ConfigError(f"{what}: bad port")
    return m.group(1), port


def _check_nets(values: list[str], what: str) -> list[str]:
    try:
        return [str(ipaddress.ip_network(v, strict=False)) for v in values]
    except ValueError as exc:
        raise ConfigError(f"{what}: {exc}") from None


def _check_ips(values: list[str], what: str) -> list[str]:
    try:
        return [str(ipaddress.ip_address(v)) for v in values]
    except ValueError as exc:
        raise ConfigError(f"{what}: {exc}") from None


def _read_secret(path: str | None) -> bytes | None:
    if not path:
        return None
    with open(path, "rb") as f:
        return f.read().strip() or None


def _crypto(sec: _Section) -> CryptoConfig:
    try:
        suites = tuple(suite_by_name(n) for n in sec.strs("suites", DEFAULT_SUITES))
        peer = tuple(sig_alg_by_name(n).name for n in sec.strs("peer_signature_algorithms", DEFAULT_PEER_SIG_ALGS))
        ca = tuple(sig_alg_by_name(n).name for n in sec.strs("ca_signature_algorithms", DEFAULT_CA_SIG_ALGS))
    except ValueError as exc:
        raise ConfigError(f"[crypto] {exc}") from None
    if not suites:
        raise ConfigError("[crypto] suites must not be empty")
    psk = None
    psk_path = sec.path("psk_file")
    if psk_path:
        try:
            psk = base64.b64decode(_read_secret(psk_path) or b"", validate=True)
        except ValueError:
            raise ConfigError("[crypto] psk_file must contain base64") from None
        if len(psk) != 32:
            raise ConfigError("[crypto] PSK must be 32 bytes (use `pqvpn genpsk`)")
    rekey = sec.int("rekey_interval", 120, 30, 3600)
    sec.check_unknown()
    return CryptoConfig(suites, peer, ca, psk, rekey)


def _load(path: str) -> tuple[dict, str]:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f), os.path.dirname(os.path.abspath(path))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None


def _top(data: dict, allowed: set[str]) -> None:
    extra = set(data) - allowed
    if extra:
        raise ConfigError(f"unknown section(s): {', '.join(sorted(extra))}")


def load_server(path: str) -> ServerConfig:
    data, base = _load(path)
    _top(data, {"server", "tunnel", "crypto", "security", "portal"})
    s = _Section(data.get("server", {}), "server", base)
    pt = _Section(data.get("portal", {}), "portal", base)
    t = _Section(data.get("tunnel", {}), "tunnel", base)
    sec = _Section(data.get("security", {}), "security", base)
    host, port = _hostport(s.str("listen", "0.0.0.0:51820"), "[server] listen")
    cfg = ServerConfig(
        listen_host=host.strip("[]"), listen_port=port,
        certificate=s.path("certificate") or _missing("server", "certificate"),
        private_key=s.path("private_key") or _missing("server", "private_key"),
        key_passphrase=_read_secret(s.path("private_key_passphrase_file")),
        ca=s.paths("ca") or _missing("server", "ca"),
        interface=t.str("interface", "pqvpn0"),
        mtu=t.int("mtu", 1420, 1280, 9000),
        addresses=t.strs("addresses"),
        dns=_check_ips(t.strs("dns"), "[tunnel] dns"),
        push_routes=_check_nets(t.strs("push_routes"), "[tunnel] push_routes"),
        nat_interface=t.str("nat_interface", ""),
        crypto=_crypto(_Section(data.get("crypto", {}), "crypto", base)),
        revoked={x.lower() for x in sec.strs("revoked_serials")},
        max_peers=sec.int("max_peers", 1024, 1, 1 << 20),
        cookie_threshold=sec.int("cookie_threshold", 64, 0, 1 << 20),
        always_require_cookie=sec.bool("always_require_cookie", False),
        handshake_rate=float(sec.int("handshake_rate_per_ip", 5, 1, 10000)),
        portal_database=pt.path("database") or "",
        portal_url=pt.str("url", ""),
    )
    if cfg.addresses:
        try:
            cfg.addresses = [str(ipaddress.ip_interface(a)) for a in cfg.addresses]
        except ValueError as exc:
            raise ConfigError(f"[tunnel] addresses: {exc}") from None
    if not _IFNAME.match(cfg.interface):
        raise ConfigError("[tunnel] interface must be 1-15 chars of [A-Za-z0-9_-]")
    for x in (s, t, sec, pt):
        x.check_unknown()
    return cfg


def load_client(path: str) -> ClientConfig:
    data, base = _load(path)
    _top(data, {"client", "tunnel", "crypto", "security"})
    c = _Section(data.get("client", {}), "client", base)
    t = _Section(data.get("tunnel", {}), "tunnel", base)
    sec = _Section(data.get("security", {}), "security", base)
    host, port = _hostport(c.str("server") or _missing("client", "server"), "[client] server")
    cfg = ClientConfig(
        server_host=host, server_port=port,
        server_name=c.str("server_name") or _missing("client", "server_name"),
        certificate=c.path("certificate") or _missing("client", "certificate"),
        private_key=c.path("private_key") or _missing("client", "private_key"),
        key_passphrase=_read_secret(c.path("private_key_passphrase_file")),
        ca=c.paths("ca") or _missing("client", "ca"),
        interface=t.str("interface", "pqvpn0"),
        mtu=t.int("mtu", 1420, 1280, 9000),
        full_tunnel=t.bool("full_tunnel", False),
        routes=_check_nets(t.strs("routes"), "[tunnel] routes"),
        use_server_dns=t.bool("use_server_dns", True),
        dns=_check_ips(t.strs("dns"), "[tunnel] dns"),
        persistent_keepalive=t.int("persistent_keepalive", 25, 0, 3600),
        crypto=_crypto(_Section(data.get("crypto", {}), "crypto", base)),
        revoked={x.lower() for x in sec.strs("revoked_serials")},
        portal_url=c.str("portal_url", ""),
    )
    if not _IFNAME.match(cfg.interface):
        raise ConfigError("[tunnel] interface must be 1-15 chars of [A-Za-z0-9_-]")
    for x in (c, t, sec):
        x.check_unknown()
    return cfg


def _missing(section: str, key: str):
    raise ConfigError(f"[{section}] {key} is required")


def load_portal(path: str) -> PortalConfig:
    data, base = _load(path)
    _top(data, {"portal", "vpn"})
    p = _Section(data.get("portal", {}), "portal", base)
    v = _Section(data.get("vpn", {}), "vpn", base)
    listen = [_hostport(x, "[portal] listen") for x in p.strs("listen", ["127.0.0.1:8800"])]
    listen = [(h.strip("[]"), port) for h, port in listen]
    tls_cert, tls_key = p.path("tls_certificate"), p.path("tls_private_key")
    if bool(tls_cert) != bool(tls_key):
        raise ConfigError("[portal] tls_certificate and tls_private_key go together")
    try:
        subnet = str(ipaddress.ip_network(v.str("subnet") or _missing("vpn", "subnet"), strict=True))
    except ValueError as exc:
        raise ConfigError(f"[vpn] subnet: {exc}") from None
    try:
        suites = [suite_by_name(n).name for n in v.strs("suites", DEFAULT_SUITES)]
        alg = sig_alg_by_name(v.str("client_algorithm", "ML-DSA-65")).name
    except ValueError as exc:
        raise ConfigError(f"[vpn] {exc}") from None
    cfg = PortalConfig(
        listen=listen,
        public_url=p.str("public_url", ""),
        database=p.path("database") or _missing("portal", "database"),
        tls_certificate=tls_cert, tls_private_key=tls_key,
        allow_insecure_http=p.bool("allow_insecure_http", False),
        issuer=p.str("issuer", "ShieldsVPN"),
        require_2fa_for_admins=p.bool("require_2fa_for_admins", True),
        session_idle=p.int("session_idle_minutes", 30, 5, 24 * 60) * 60,
        session_max=p.int("session_max_hours", 12, 1, 24 * 30) * 3600,
        server_name=v.str("server_name") or _missing("vpn", "server_name"),
        endpoint=v.str("endpoint") or _missing("vpn", "endpoint"),
        subnet=subnet,
        reserved_addresses=set(_check_ips(v.strs("reserved_addresses"), "[vpn] reserved_addresses")),
        ca_certificate=v.path("ca_certificate") or _missing("vpn", "ca_certificate"),
        ca_private_key=v.path("ca_private_key") or _missing("vpn", "ca_private_key"),
        ca_passphrase=_read_secret(v.path("ca_passphrase_file")),
        psk_file=v.path("psk_file"),
        client_algorithm=alg,
        certificate_days=float(v.int("certificate_days", 90, 1, 3650)),
        suites=suites,
        vpn_portal_url=v.str("portal_url_in_vpn", ""),
        allowed_hosts=[h.lower() for h in p.strs("allowed_hosts")],
        allow_internal_smtp=p.bool("allow_internal_smtp", False),
    )
    _hostport(cfg.endpoint, "[vpn] endpoint")
    for x in (p, v):
        x.check_unknown()
    return cfg
