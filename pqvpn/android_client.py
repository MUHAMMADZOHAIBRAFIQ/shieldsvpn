"""Android client integration: runs the unchanged pqvpn ``ClientNode`` inside an Android ``VpnService``.

The Android app (``android-app/``) embeds Python with Chaquopy and drives this module through three
entry points:

``import_profile(zip_bytes, dest_dir)``
    Validates a profile ZIP downloaded from the portal (the same file the desktop clients use) entirely in
    memory, writes only the *public* parts (``client.toml``, the certificate, the CA certificate) to
    ``dest_dir`` and hands the private key and the optional PSK back to the caller, which encrypts them
    with the Android Keystore.  The private key is never written to disk by this module.

``Session(profile_dir, key_pem, psk_b64, bridge)``
    One VPN connection.  ``run()`` blocks (call it on a dedicated thread) until ``stop()`` is called from
    any thread.  ``network_changed()`` asks for an immediate re-handshake after Android switches networks.

``tunnel_settings(server_config, cfg, cert)``
    Turns the server's *authenticated* configuration push into the exact interface settings that
    ``VpnService.Builder`` needs, after checking it against the client certificate.

How the TUN interface is created
    ``VpnService.Builder.establish()`` needs the interface address, routes and DNS servers before it
    returns a TUN descriptor, but the server sends routes/DNS/prefix length only inside the encrypted,
    signature-authenticated AUTH_R message.  The session therefore runs the handshake *first*, with no TUN
    (nothing is captured or routed yet), validates the pushed configuration (``tunnel_settings``: the
    pushed addresses must be the host addresses in the CA-signed client certificate), and only then asks
    the app to ``establish()`` the interface -- once, with the real values.  Later re-handshakes (rekeys,
    roaming, reconnects) keep the same TUN, so traffic is held inside the tunnel while the session recovers.

The ``bridge`` object is implemented in Kotlin (``PythonVpnBridge``) and must provide:
    protectSocket(fd: int) -> bool          VpnService.protect() for the UDP socket
    establishTunnel(settings_json: str) -> int   build the interface; returns a detached fd or -1
    onState(state: str, info_json: str)          UI / notification updates (called on the loop thread)

Nothing in this module imports ``pqvpn.crypto.ossl`` at import time, so the app can set
``PQVPN_LIBCRYPTO`` (via ``configure``) before the native library is loaded.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import io
import ipaddress
import json
import logging
import os
import posixpath
import re
import socket
import threading
import time
import tomllib
import zipfile

log = logging.getLogger("pqvpn.android")

MAX_PROFILE_ZIP = 4 << 20          # a portal profile is ~30 KB; refuse anything absurd
MAX_PROFILE_MEMBER = 512 << 10
MAX_ROUTES = 256
MAX_DNS = 8
MIN_MTU, MAX_MTU = 1280, 9000
READ_BATCH = 128
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")
_PSK_LINE = re.compile(r"^[ \t]*psk_file[ \t]*=.*(?:\r?\n|$)", re.M)


class ProfileError(Exception):
    """The imported profile is unusable; the message is safe to show to the user."""


class TunnelConfigError(Exception):
    """The server's pushed configuration cannot be applied safely."""


def configure(native_lib_dir: str, lib_name: str = "libcrypto_pqvpn.so") -> str:
    """Point pqvpn at the OpenSSL >= 3.5 libcrypto packaged in the APK.  Call before anything else."""
    path = os.path.join(native_lib_dir, lib_name)
    os.environ["PQVPN_LIBCRYPTO"] = path
    return path


def openssl_version() -> str:
    from .crypto import ossl
    return ossl.version_string()


# ====================================================================== profile import

def _member_files(data: bytes) -> tuple[dict[str, bytes], str]:
    """Read the files next to client.toml from a profile ZIP, without extracting anything."""
    if len(data) > MAX_PROFILE_ZIP:
        raise ProfileError("This file is too large to be a ShieldsVPN profile.")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ProfileError("This is not a ZIP file. Choose the profile .zip downloaded from the portal.") from None
    with z:
        tomls = [i for i in z.infolist() if not i.is_dir() and posixpath.basename(i.filename) == "client.toml"]
        if len(tomls) != 1:
            raise ProfileError("The ZIP must contain exactly one client.toml (a ShieldsVPN profile).")
        folder = posixpath.dirname(tomls[0].filename)
        files: dict[str, bytes] = {}
        for info in z.infolist():
            if info.is_dir() or posixpath.dirname(info.filename) != folder:
                continue
            name = posixpath.basename(info.filename)
            if not _SAFE_NAME.match(name) or info.file_size > MAX_PROFILE_MEMBER:
                continue  # never used: only files named by client.toml are read below
            with z.open(info) as f:
                blob = f.read(MAX_PROFILE_MEMBER + 1)
            if len(blob) > MAX_PROFILE_MEMBER:
                continue
            files[name] = blob
    return files, folder


def _referenced(raw: dict, section: str, key: str, required: bool = True) -> str | None:
    value = raw.get(section, {}).get(key)
    if value is None:
        if required:
            raise ProfileError(f"client.toml has no [{section}] {key}.")
        return None
    if not isinstance(value, str) or not _SAFE_NAME.match(value):
        raise ProfileError(f"client.toml [{section}] {key} must name a file inside the profile.")
    return value


def import_profile(zip_bytes, dest_dir: str) -> dict:
    """Validate a portal profile ZIP and install its public parts into ``dest_dir`` (must be empty/new).

    Returns ``{"summary": {...}, "secrets": {"key_pem": str, "psk": str}}``.  Raises ProfileError with a
    user-presentable message.  ``secrets`` must be stored encrypted by the caller and never logged.
    """
    from . import pki
    from .config import ConfigError, load_client
    from .crypto import ossl

    data = bytes(zip_bytes)
    files, _folder = _member_files(data)
    try:
        toml_text = files["client.toml"].decode("utf-8")
        raw = tomllib.loads(toml_text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"client.toml is not valid: {exc}") from None
    cert_name = _referenced(raw, "client", "certificate")
    key_name = _referenced(raw, "client", "private_key")
    ca_value = raw.get("client", {}).get("ca")
    if not isinstance(ca_value, list) or not ca_value:
        raise ProfileError("client.toml has no [client] ca list.")
    ca_names = []
    for v in ca_value:
        if not isinstance(v, str) or not _SAFE_NAME.match(v):
            raise ProfileError("client.toml [client] ca must name files inside the profile.")
        ca_names.append(v)
    if raw.get("client", {}).get("private_key_passphrase_file"):
        raise ProfileError("Passphrase-protected private keys are not supported on Android yet. "
                           "Download a fresh profile from the portal.")
    psk_name = _referenced(raw, "crypto", "psk_file", required=False)
    for name in [cert_name, key_name, *ca_names] + ([psk_name] if psk_name else []):
        if name not in files:
            raise ProfileError(f"The profile is incomplete: {name} is missing.")

    psk_b64 = ""
    if psk_name:
        try:
            psk = base64.b64decode(files[psk_name].strip(), validate=True)
        except ValueError:
            raise ProfileError("psk.key in the profile is not valid base64.") from None
        if len(psk) != 32:
            raise ProfileError("psk.key in the profile must hold a 32-byte key.")
        psk_b64 = base64.b64encode(psk).decode()

    # client.toml is stored without psk_file: the PSK lives only in the Keystore-encrypted secrets blob.
    stored_toml = _PSK_LINE.sub("", toml_text)
    if "psk_file" in tomllib.loads(stored_toml).get("crypto", {}):
        raise ProfileError("client.toml has an unexpected psk_file entry.")

    os.makedirs(dest_dir, exist_ok=True)
    if os.listdir(dest_dir):
        raise ProfileError("internal error: profile staging directory is not empty")
    _write(os.path.join(dest_dir, "client.toml"), stored_toml.encode("utf-8"))
    for name in [cert_name, *ca_names]:
        _write(os.path.join(dest_dir, name), files[name])

    try:
        cfg = load_client(os.path.join(dest_dir, "client.toml"))
    except ConfigError as exc:
        raise ProfileError(f"client.toml: {exc}") from None
    try:
        cert = pki.Certificate.load(cfg.certificate)
        key = ossl.private_from_pem(files[key_name])
        identity = pki.Identity(cert, key)
        trust = _trust(cfg)
        trust.verify(cert, pki.ROLE_CLIENT)
    except ossl.OpenSSLError:
        raise ProfileError("The private key in the profile cannot be read.") from None
    except pki.CertError as exc:
        raise ProfileError(f"The profile's certificate is not usable: {exc}") from None
    except (OSError, ValueError) as exc:
        raise ProfileError(f"The profile cannot be read: {exc}") from None
    key_pem = files[key_name].decode("ascii")
    return {"summary": profile_summary(cfg, identity.cert), "secrets": {"key_pem": key_pem, "psk": psk_b64}}


def import_profile_json(zip_bytes, dest_dir: str) -> str:
    """``import_profile`` for the Kotlin side: {"ok": true, "summary", "secrets"} or {"ok": false, "error"}."""
    try:
        return json.dumps({"ok": True, **import_profile(zip_bytes, dest_dir)})
    except ProfileError as exc:
        return json.dumps({"ok": False, "error": str(exc)})


def load_profile_summary_json(profile_dir: str) -> str:
    try:
        return json.dumps({"ok": True, "summary": load_profile_summary(profile_dir)})
    except ProfileError as exc:
        return json.dumps({"ok": False, "error": str(exc)})


def _write(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _trust(cfg):
    from . import pki
    return pki.TrustStore.load(cfg.ca, peer_algs=cfg.crypto.peer_sig_algs, ca_algs=cfg.crypto.ca_sig_algs,
                               revoked=cfg.revoked)


def profile_summary(cfg, cert) -> dict:
    from .crypto.suites import describe_suite
    return {
        "account": cert.subject,
        "server": f"{cfg.server_host}:{cfg.server_port}",
        "server_name": cfg.server_name,
        "tunnel_address": cert.addresses[0] if cert.addresses else "",
        "expires": cert.not_after,
        "serial": cert.serial_hex,
        "key_alg": cert.key_alg.name,
        "full_tunnel": cfg.full_tunnel,
        "encryption": describe_suite(cfg.crypto.suites[0].name),
        "portal_url": cfg.portal_url,
        "has_psk": cfg.crypto.psk is not None,
    }


def load_profile_summary(profile_dir: str) -> dict:
    """Summary of an installed profile (public parts only), for the UI."""
    from . import pki
    from .config import ConfigError, load_client
    try:
        cfg = load_client(os.path.join(profile_dir, "client.toml"))
        return profile_summary(cfg, pki.Certificate.load(cfg.certificate))
    except (ConfigError, pki.CertError, OSError) as exc:
        raise ProfileError(f"The installed profile is damaged ({exc}). Import it again.") from None


# ====================================================================== tunnel settings

def _family(ip) -> str:
    return "ipv4" if ip.version == 4 else "ipv6"


def tunnel_settings(server_config: dict, cfg, cert) -> dict:
    """Validate the authenticated server push and build the VpnService.Builder settings.

    Mirrors the desktop client's ``ClientNode._apply_config`` (client routes/DNS override the pushed ones,
    ``full_tunnel`` adds default routes), plus Android-specific leak handling: a family (IPv4/IPv6) with no
    tunnel address is *blocked* in full-tunnel mode and *bypasses* the VPN in split-tunnel mode.
    """
    if not isinstance(server_config, dict):
        raise TunnelConfigError("the server sent no tunnel configuration")
    own_hosts = {n.network_address for n in cert.networks() if n.num_addresses == 1}

    raw_addrs = server_config.get("addresses")
    if not isinstance(raw_addrs, list) or not raw_addrs:
        raise TunnelConfigError("the server assigned no tunnel address")
    addresses = []
    for a in raw_addrs:
        try:
            iface = ipaddress.ip_interface(a)
        except (TypeError, ValueError):
            raise TunnelConfigError(f"the server sent an invalid tunnel address {a!r}") from None
        if iface.ip not in own_hosts:
            raise TunnelConfigError(f"the server assigned {iface.ip}, which is not an address in your "
                                    "certificate; refusing to configure the tunnel")
        if iface.network.prefixlen == 0:
            raise TunnelConfigError(f"the server sent a tunnel address with a /0 prefix ({a})")
        if all(iface.ip != x.ip for x in addresses):
            addresses.append(iface)
    families = {_family(a.ip) for a in addresses}

    if cfg.routes:
        route_src, origin = list(cfg.routes), "profile"
    else:
        route_src, origin = server_config.get("routes", []), "server"
        if not isinstance(route_src, list):
            raise TunnelConfigError("the server sent an invalid route list")
    routes = []
    for r in route_src:
        try:
            net = ipaddress.ip_network(r, strict=False)
        except (TypeError, ValueError):
            raise TunnelConfigError(f"invalid route {r!r} from the {origin}") from None
        if net not in routes:
            routes.append(net)
    if cfg.full_tunnel:
        for fam, default in (("ipv4", ipaddress.ip_network("0.0.0.0/0")), ("ipv6", ipaddress.ip_network("::/0"))):
            if fam in families and default not in routes:
                routes.append(default)
    full = {_family(n.network_address) for n in routes if n.prefixlen == 0}
    full_tunnel = bool(full)

    dropped = []
    kept_routes = []
    for n in routes:
        if _family(n.network_address) in families:
            kept_routes.append(n)
        else:
            dropped.append(str(n))  # unusable without a tunnel address of that family
    if len(kept_routes) > MAX_ROUTES:
        raise TunnelConfigError(f"too many routes ({len(kept_routes)}; at most {MAX_ROUTES})")
    if not kept_routes:
        raise TunnelConfigError("no routes go through the tunnel (neither the server nor the profile set any)")

    if cfg.dns:
        dns_src = list(cfg.dns)
    elif cfg.use_server_dns:
        dns_src = server_config.get("dns", [])
        if not isinstance(dns_src, list):
            raise TunnelConfigError("the server sent an invalid DNS list")
    else:
        dns_src = []
    dns = []
    for d in dns_src:
        try:
            ip = ipaddress.ip_address(d)
        except (TypeError, ValueError):
            raise TunnelConfigError(f"invalid DNS server {d!r}") from None
        if _family(ip) not in families:
            dropped.append(str(ip))
        elif str(ip) not in dns:
            dns.append(str(ip))
    dns = dns[:MAX_DNS]
    if full_tunnel and not dns:
        # Verified on Android 16: when a VPN network has no DNS servers, the system resolver uses the underlying
        # network's resolvers *outside* the tunnel, so every name an app looks up would leak to the local network
        # even though all other traffic is tunnelled.  Fail closed instead of advertising a leaky full tunnel.
        raise TunnelConfigError("full tunnel needs a DNS server inside the tunnel, but neither the server nor the "
                                "profile provides one; refusing to connect because name lookups would bypass the "
                                "VPN. Ask the operator to set [tunnel] dns or a plan DNS in the portal.")

    mtu = cfg.mtu
    srv_mtu = server_config.get("mtu")
    if isinstance(srv_mtu, int) and not isinstance(srv_mtu, bool) and MIN_MTU <= srv_mtu <= MAX_MTU:
        mtu = min(mtu, srv_mtu)

    other = {"ipv4", "ipv6"} - families
    return {
        "session": cfg.server_name,
        "mtu": mtu,
        "addresses": [{"address": str(a.ip), "prefix": a.network.prefixlen} for a in addresses],
        "routes": [{"address": str(n.network_address), "prefix": n.prefixlen} for n in kept_routes],
        "dns": dns,
        "full_tunnel": full_tunnel,
        # Families with no tunnel address: blocked when tunnelling everything (no IPv6 leak), otherwise
        # left to the normal network (split tunnel).
        "blocked_families": sorted(other) if full_tunnel else [],
        "bypass_families": [] if full_tunnel else sorted(other),
        "dropped": dropped,
    }


# ====================================================================== TUN adapter

class AndroidTun:
    """The pqvpn TUN contract (start / write / close) over a VpnService TUN file descriptor.

    The descriptor comes from ``ParcelFileDescriptor.detachFd()``, so this object owns it and closes it.
    I/O is non-blocking and runs on the asyncio loop thread only (``loop.add_reader``): reads are drained
    in bounded batches, writes are serialised by the loop and a full kernel queue drops the packet (like a
    congested link) instead of blocking.  Before ``attach`` the device is a black hole, which is what the
    client needs while the first handshake runs.
    """

    name = "android-vpn"

    def __init__(self, mtu: int):
        self.mtu = mtu
        self.fd = -1
        self.versions: set[int] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sink = None
        self._reading = False
        self.closed = False
        self.rx_packets = self.tx_packets = self.dropped = 0

    def start(self, loop: asyncio.AbstractEventLoop, on_packets) -> None:
        self._loop, self._sink = loop, on_packets
        self._maybe_read()

    def attach(self, fd: int, versions: set[int]) -> None:
        if self.closed:
            os.close(fd)
            raise RuntimeError("TUN adapter already closed")
        if self.fd >= 0:
            raise RuntimeError("TUN descriptor already attached")
        os.set_blocking(fd, False)
        self.fd, self.versions = fd, set(versions)
        self._maybe_read()

    def _maybe_read(self) -> None:
        if self._loop is not None and self.fd >= 0 and not self._reading:
            self._loop.add_reader(self.fd, self._readable)
            self._reading = True

    def _readable(self) -> None:
        batch = []
        for _ in range(READ_BATCH):
            try:
                pkt = os.read(self.fd, 65535)
            except (BlockingIOError, InterruptedError):
                break
            except OSError as exc:  # descriptor revoked (another VPN took over, interface gone)
                log.warning("TUN read failed: %s", exc)
                self._stop_reading()
                return
            if not pkt:
                break
            if (pkt[0] >> 4) not in self.versions:
                self.dropped += 1
                continue
            batch.append(pkt)
        if batch:
            self.rx_packets += len(batch)
            self._sink(batch)

    def write(self, packet: bytes) -> None:
        if self.fd < 0:
            self.dropped += 1
            return
        try:
            os.write(self.fd, packet)
            self.tx_packets += 1
        except (BlockingIOError, InterruptedError):
            self.dropped += 1
        except OSError as exc:
            self.dropped += 1
            log.debug("TUN write dropped: %s", exc)

    def _stop_reading(self) -> None:
        if self._reading and self._loop is not None:
            try:
                self._loop.remove_reader(self.fd)
            except (ValueError, OSError):
                pass
        self._reading = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._stop_reading()
        self._sink = None
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            try:
                os.close(fd)  # closing the last reference tears the Android VPN interface down
            except OSError:
                pass


# ====================================================================== session

class Session:
    """One VPN connection, driven from a Kotlin thread.  All node/TUN work happens on the asyncio loop."""

    def __init__(self, profile_dir: str, key_pem: str, psk_b64: str, bridge):
        self.profile_dir = profile_dir
        self._key_pem = str(key_pem)
        self._psk_b64 = str(psk_b64 or "")
        self.bridge = bridge
        self.loop: asyncio.AbstractEventLoop | None = None
        self.node = None
        self.tun: AndroidTun | None = None
        self.settings: dict | None = None
        self._stop: asyncio.Event | None = None
        self._stop_requested = False
        self._lock = threading.Lock()
        self.last_error = ""

    # -------------------------------------------------------------- thread-safe controls
    def stop(self) -> None:
        with self._lock:
            self._stop_requested = True
            loop, ev = self.loop, self._stop
        if loop is not None and ev is not None:
            try:
                loop.call_soon_threadsafe(ev.set)
            except RuntimeError:  # loop already closed
                pass

    def stats_json(self) -> str:
        """Traffic counters for the UI (callable from any thread; plain int reads under the GIL).

        rx = bytes of inner IP packets received from the server (download), tx = sent to it (upload).
        """
        node, tun = self.node, self.tun
        peer = node.peer if node is not None else None
        return json.dumps({
            "rx_bytes": peer.rx_bytes if peer else 0,
            "tx_bytes": peer.tx_bytes if peer else 0,
            "rx_packets": tun.tx_packets if tun else 0,   # packets written into the TUN = received
            "tx_packets": tun.rx_packets if tun else 0,   # packets read from the TUN = sent
        })

    def network_changed(self) -> None:
        with self._lock:
            loop = self.loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(self._on_network_changed)
            except RuntimeError:
                pass

    # -------------------------------------------------------------- run
    def run(self) -> str:
        """Blocking.  Returns "" after an orderly stop, or a user-presentable error message."""
        if not logging.getLogger().handlers:
            logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        try:
            asyncio.run(self._main())
        except Exception as exc:  # noqa: BLE001 -- report every failure to the UI instead of crashing
            self.last_error = self.last_error or _friendly(exc)
            log.error("VPN session failed: %s", self.last_error)
        finally:
            self._report("disconnected", {"message": self.last_error} if self.last_error else {})
        return self.last_error

    def _load(self):
        from . import pki
        from .config import ConfigError, load_client
        from .crypto import ossl
        try:
            cfg = load_client(os.path.join(self.profile_dir, "client.toml"))
        except ConfigError as exc:
            raise ProfileError(f"The installed profile is damaged ({exc}). Import it again.") from None
        if self._psk_b64:
            cfg.crypto = dataclasses.replace(cfg.crypto, psk=base64.b64decode(self._psk_b64, validate=True))
        cert = pki.Certificate.load(cfg.certificate)
        try:
            identity = pki.Identity(cert, ossl.private_from_pem(self._key_pem.encode("ascii")))
        except (ossl.OpenSSLError, pki.CertError):
            raise ProfileError("The stored private key does not match the profile. Import the profile again.") \
                from None
        self._key_pem = ""  # the key now lives only inside the OpenSSL object
        trust = _trust(cfg)
        try:
            trust.verify(cert, pki.ROLE_CLIENT)
        except pki.CertError as exc:
            raise ProfileError(f"Your profile can no longer be used ({exc}). Download a new one from the "
                               "portal.") from None
        return cfg, identity, trust

    async def _main(self) -> None:
        from .node import ClientNode, make_udp_socket, open_udp_endpoint

        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        with self._lock:
            self.loop, self._stop = loop, stop
            if self._stop_requested:
                return
        cfg, identity, trust = self._load()
        self._report("connecting", {"server": cfg.server_name, "endpoint": f"{cfg.server_host}:{cfg.server_port}"})
        try:
            infos = await loop.getaddrinfo(cfg.server_host, cfg.server_port, type=socket.SOCK_DGRAM)
        except OSError as exc:
            raise ProfileError(f"Cannot find the server {cfg.server_host} ({exc.strerror or exc}). "
                               "Check your internet connection.") from None
        family, endpoint = infos[0][0], infos[0][4]
        sock = make_udp_socket("::" if family == socket.AF_INET6 else "0.0.0.0", 0, family)
        try:
            if not self.bridge.protectSocket(sock.fileno()):
                raise ProfileError("Android refused to exempt the VPN's own connection from the tunnel.")
        except Exception:
            sock.close()
            raise
        self.tun = AndroidTun(cfg.mtu)
        node = self.node = ClientNode(cfg, identity, trust, self.tun, endpoint, None, self._on_state)
        try:
            await open_udp_endpoint(node, sock)  # drains bursts per wake-up (node.BatchedUdpTransport)
            self.tun.start(loop, node.on_tun_packets)
            node.start_timers()
            log.info("connecting to %s (%s:%d) as %s", cfg.server_name, endpoint[0], endpoint[1],
                     identity.cert.subject)
            node.start_handshake(time.monotonic())
            waiters = [asyncio.ensure_future(stop.wait()), asyncio.ensure_future(node.closed.wait())]
            try:
                await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for w in waiters:
                    w.cancel()
        finally:
            node.close()
            self.tun.close()
            log.info("VPN session closed")

    # -------------------------------------------------------------- callbacks (loop thread)
    def _on_state(self, state: str, info: dict) -> None:
        info = dict(info)
        if state == "connected" and self.tun is not None and self.tun.fd < 0:
            try:
                self._establish()
            except Exception as exc:  # noqa: BLE001 -- never run a tunnel we could not configure
                self.last_error = _friendly(exc)
                log.error("cannot configure the tunnel: %s", self.last_error)
                self._report("error", {"message": self.last_error})
                if self._stop is not None:
                    self._stop.set()
                return
        if state == "connected":
            from .crypto.suites import describe_suite
            info["encryption"] = describe_suite(info.get("suite", ""))
        if state == "connected" and self.settings:
            info.update(routes=[f"{r['address']}/{r['prefix']}" for r in self.settings["routes"]],
                        dns=self.settings["dns"], full_tunnel=self.settings["full_tunnel"],
                        mtu=self.settings["mtu"],
                        tunnel_address=", ".join(f"{a['address']}/{a['prefix']}"
                                                 for a in self.settings["addresses"]))
        if state == "error":
            self.last_error = info.get("message", "")
        self._report(state, info)

    def _establish(self) -> None:
        node = self.node
        settings = tunnel_settings(node.server_config, node.cfg, node.identity.cert)
        fd = int(self.bridge.establishTunnel(json.dumps(settings)))
        if fd < 0:
            raise TunnelConfigError("Android did not create the VPN interface (VPN permission revoked, or "
                                    "another VPN app is active).")
        versions = {ipaddress.ip_address(a["address"]).version for a in settings["addresses"]}
        self.tun.attach(fd, versions)
        self.settings = settings
        log.info("tunnel up: %s, routes %s, dns %s, mtu %d%s",
                 ", ".join(f"{a['address']}/{a['prefix']}" for a in settings["addresses"]),
                 ", ".join(f"{r['address']}/{r['prefix']}" for r in settings["routes"]),
                 ", ".join(settings["dns"]) or "-", settings["mtu"],
                 " (full tunnel)" if settings["full_tunnel"] else "")

    def _on_network_changed(self) -> None:
        node = self.node
        if node is None or node.closed.is_set():
            return
        now = time.monotonic()
        if node.hs is None:
            log.info("network changed: re-handshaking")
            node.next_attempt = 0.0
            node.start_handshake(now)
        else:
            # A handshake is already running (perhaps started on the network that just vanished): resend its
            # cached flight now on the new path instead of waiting out the backed-off retransmit timer.
            # Retransmitting the identical datagrams is what the protocol requires (protocol.fragment()).
            log.info("network changed: resending the handshake in progress")
            node.hs_rto = 1.0
            node._send_flight(now)

    def _report(self, state: str, info: dict) -> None:
        try:
            self.bridge.onState(state, json.dumps(info, default=str))
        except Exception:  # noqa: BLE001 -- a UI failure must not break the tunnel
            log.exception("state callback failed")


def _friendly(exc: BaseException) -> str:
    if isinstance(exc, (ProfileError, TunnelConfigError)):
        return str(exc)
    name = type(exc).__name__
    if name == "OpenSSLError":
        return f"The cryptography library failed to load or run: {exc}"
    return f"{name}: {exc}" if str(exc) else name
