"""Process-level runners for the server, the client and the loopback self-test."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import socket
import struct
import sys
import time

from . import pki
from .config import ClientConfig, CryptoConfig, ServerConfig
from .crypto import ossl
from .crypto.suites import DEFAULT_CA_SIG_ALGS, DEFAULT_PEER_SIG_ALGS, SUITES_BY_NAME, sig_alg_by_name
from .netcfg import NetConfig
from .node import ClientNode, ServerNode, make_udp_socket
from .tun import MemoryTun, open_tun

log = logging.getLogger("pqvpn")


def _trust(cfg) -> pki.TrustStore:
    return pki.TrustStore.load(cfg.ca, peer_algs=cfg.crypto.peer_sig_algs,
                               ca_algs=cfg.crypto.ca_sig_algs, revoked=cfg.revoked)


async def _wait_for_shutdown(node) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
    waiters = [asyncio.create_task(stop.wait()), asyncio.create_task(node.closed.wait())]
    try:
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for w in waiters:
            w.cancel()


def _check_privileges() -> None:
    if sys.platform == "win32":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise SystemExit("pqvpn must run as Administrator on Windows (TUN adapter + routes).")
    elif hasattr(os, "geteuid") and os.geteuid() != 0:
        log.warning("not running as root; TUN creation will fail unless CAP_NET_ADMIN is granted")


async def run_server(cfg: ServerConfig) -> None:
    identity = pki.Identity.load(cfg.certificate, cfg.private_key, cfg.key_passphrase)
    trust = _trust(cfg)
    access = None
    if cfg.portal_database:
        from .portal.access import PortalAccess
        access = PortalAccess(cfg.portal_database, cfg.portal_url)
        log.info("access control: portal accounts in %s", cfg.portal_database)
    _check_privileges()
    tun = open_tun(cfg.interface, cfg.mtu)
    net = NetConfig(tun.name, getattr(tun, "if_index", None))
    node = None
    try:
        node = ServerNode(cfg, identity, trust, tun, access)
        net.configure_interface([str(a) for a in node.addresses], cfg.mtu)
        if cfg.nat_interface:
            net.enable_forwarding_nat([str(a.network) for a in node.addresses], cfg.nat_interface)
        family = socket.AF_INET6 if ":" in cfg.listen_host else socket.AF_INET
        sock = make_udp_socket(cfg.listen_host, cfg.listen_port, family)
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: node, sock=sock)
        tun.start(loop, node.on_tun_packets)
        node.start_timers()
        log.info("pqvpn server '%s' listening on %s:%d, tunnel %s %s", identity.cert.subject,
                 cfg.listen_host, cfg.listen_port, tun.name, ", ".join(map(str, node.addresses)))
        log.info("suites (preference order): %s", ", ".join(s.name for s in cfg.crypto.suites))
        await _wait_for_shutdown(node)
    finally:
        log.info("shutting down")
        if node:
            node.close()
        tun.close()
        net.teardown()


async def run_client(cfg: ClientConfig, on_state=None) -> None:
    identity = pki.Identity.load(cfg.certificate, cfg.private_key, cfg.key_passphrase)
    trust = _trust(cfg)
    _check_privileges()
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(cfg.server_host, cfg.server_port, type=socket.SOCK_DGRAM)
    family, endpoint = infos[0][0], infos[0][4]
    tun = open_tun(cfg.interface, cfg.mtu)
    net = NetConfig(tun.name, getattr(tun, "if_index", None))
    node = None
    try:
        sock = make_udp_socket("::" if family == socket.AF_INET6 else "0.0.0.0", 0, family)
        node = ClientNode(cfg, identity, trust, tun, endpoint, net, on_state)
        await loop.create_datagram_endpoint(lambda: node, sock=sock)
        tun.start(loop, node.on_tun_packets)
        node.start_timers()
        log.info("connecting to %s (%s:%d) as '%s'...", cfg.server_name, endpoint[0], endpoint[1],
                 identity.cert.subject)
        node.start_handshake(time.monotonic())
        await _wait_for_shutdown(node)
    finally:
        log.info("disconnecting")
        if node:
            node.close()
        tun.close()
        net.teardown()
        if on_state is not None:
            on_state("disconnected", {})


# ====================================================================== self-test

def icmp_echo(src: str, dst: str, seq: int, payload: bytes = b"pqvpn-selftest") -> bytes:
    def csum(b: bytes) -> int:
        if len(b) % 2:
            b += b"\0"
        s = sum(struct.unpack(f">{len(b) // 2}H", b))
        s = (s >> 16) + (s & 0xFFFF)
        return ~(s + (s >> 16)) & 0xFFFF

    icmp = struct.pack(">BBHHH", 8, 0, 0, 0x1234, seq) + payload
    icmp = icmp[:2] + struct.pack(">H", csum(icmp)) + icmp[4:]
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), seq, 0, 64, 1, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    hdr = hdr[:10] + struct.pack(">H", csum(hdr)) + hdr[12:]
    return hdr + icmp


class TestPKI:
    """Ephemeral in-memory PKI for tests and the self-test."""

    def __init__(self, ca_alg="SLH-DSA-SHA2-192s", peer_alg="ML-DSA-65"):
        ca_a, peer_a = sig_alg_by_name(ca_alg), sig_alg_by_name(peer_alg)
        self.ca_key = ca_a.generate()
        self.ca_cert = pki.self_sign_ca("Self-test Root CA", self.ca_key, ca_a, 1)
        self.ca_alg, self.peer_alg = ca_a, peer_a
        self._cache: dict[tuple, pki.Identity] = {}

    def identity(self, role: int, subject: str, addresses: list[str], days: float = 1) -> pki.Identity:
        key_ = (role, subject, tuple(addresses), days)
        if key_ not in self._cache:
            self._cache[key_] = self._new_identity(role, subject, addresses, days)
        return self._cache[key_]

    def _new_identity(self, role: int, subject: str, addresses: list[str], days: float) -> pki.Identity:
        key = self.peer_alg.generate()
        cert = pki.issue(role=role, subject=subject, key_alg=self.peer_alg,
                         public_key=self.peer_alg.public_bytes(key), addresses=addresses, days=days,
                         issuer_key=self.ca_key, issuer_alg=self.ca_alg,
                         issuer_public=self.ca_cert.public_key)
        return pki.Identity(cert, key)

    def trust(self, revoked=None) -> pki.TrustStore:
        return pki.TrustStore([self.ca_cert], peer_algs=DEFAULT_PEER_SIG_ALGS + ("ML-DSA-44",),
                              ca_algs=DEFAULT_CA_SIG_ALGS + ("SLH-DSA-SHA2-128s",), revoked=revoked)


def crypto_cfg(suites=None, psk=None, rekey=120) -> CryptoConfig:
    names = suites or ["MLKEM768-X25519_CHACHA20POLY1305_SHA384"]
    return CryptoConfig(tuple(SUITES_BY_NAME[n] for n in names), DEFAULT_PEER_SIG_ALGS,
                        DEFAULT_CA_SIG_ALGS, psk, rekey)


def server_cfg(crypto: CryptoConfig, **kw) -> ServerConfig:
    base = dict(listen_host="127.0.0.1", listen_port=0, certificate="", private_key="", key_passphrase=None,
                ca=[], interface="mem0", mtu=1420, addresses=["10.66.0.1/24"], dns=["10.66.0.1"],
                push_routes=[], nat_interface="", crypto=crypto, revoked=set(), max_peers=16,
                cookie_threshold=64, always_require_cookie=False, handshake_rate=50.0)
    base.update(kw)
    return ServerConfig(**base)


def client_cfg(crypto: CryptoConfig, port: int, **kw) -> ClientConfig:
    base = dict(server_host="127.0.0.1", server_port=port, server_name="vpn.test", certificate="",
                private_key="", key_passphrase=None, ca=[], interface="mem1", mtu=1420, full_tunnel=False,
                routes=[], use_server_dns=True, dns=[], persistent_keepalive=0, crypto=crypto)
    base.update(kw)
    return ClientConfig(**base)


async def loopback_pair(tp: TestPKI, scfg: ServerConfig, ccfg_kw: dict | None = None,
                        client_identity=None, server_trust=None, client_crypto=None, server_identity=None,
                        access=None, client_trust=None):
    """Start a server and a client wired together over 127.0.0.1 with memory TUNs."""
    loop = asyncio.get_running_loop()
    s_id = server_identity or tp.identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"])
    c_id = client_identity or tp.identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
    s_tun, c_tun = MemoryTun("s"), MemoryTun("c")
    server = ServerNode(scfg, s_id, server_trust or tp.trust(), s_tun, access)
    s_tr, _ = await loop.create_datagram_endpoint(
        lambda: server, sock=make_udp_socket("127.0.0.1", 0, socket.AF_INET))
    port = s_tr.get_extra_info("sockname")[1]
    ccfg = client_cfg(client_crypto or scfg.crypto, port, **(ccfg_kw or {}))
    client = ClientNode(ccfg, c_id, client_trust or tp.trust(), c_tun, ("127.0.0.1", port))
    await loop.create_datagram_endpoint(
        lambda: client, sock=make_udp_socket("127.0.0.1", 0, socket.AF_INET))
    s_tun.start(loop, server.on_tun_packets)
    c_tun.start(loop, client.on_tun_packets)
    server.start_timers()
    client.start_timers()
    return server, client, s_tun, c_tun


async def selftest() -> bool:
    print(f"OpenSSL: {ossl.version_string()}")
    ok = True
    t0 = time.perf_counter()
    tp = TestPKI()
    print(f"Test PKI: {tp.ca_alg.name} root CA -> {tp.peer_alg.name} device certificates "
          f"({(time.perf_counter() - t0) * 1000:.0f} ms incl. hash-based CA signing)")
    for suite_name in SUITES_BY_NAME:
        scfg = server_cfg(crypto_cfg([suite_name]))
        server, client, s_tun, c_tun = await loopback_pair(tp, scfg)
        try:
            t0 = time.perf_counter()
            client.start_handshake(time.monotonic())
            await asyncio.wait_for(client.connected.wait(), 10)
            hs_ms = (time.perf_counter() - t0) * 1000
            c_tun.inject(icmp_echo("10.66.0.2", "10.66.0.1", 1))
            got = await asyncio.wait_for(s_tun.written.get(), 5)
            s_tun.inject(icmp_echo("10.66.0.1", "10.66.0.2", 2))
            back = await asyncio.wait_for(c_tun.written.get(), 5)
            good = got[12:16] == ipaddress.IPv4Address("10.66.0.2").packed and back[16:20] == got[12:16]
            print(f"  [{'PASS' if good else 'FAIL'}] {suite_name:<42} handshake {hs_ms:6.1f} ms, "
                  f"client address {', '.join(client.server_config.get('addresses', []))}")
            ok &= good
        except Exception as exc:
            print(f"  [FAIL] {suite_name}: {exc!r}")
            ok = False
        finally:
            client.close()
            server.close()
    return ok
