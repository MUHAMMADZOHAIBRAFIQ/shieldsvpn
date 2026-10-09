"""Server and client nodes: UDP <-> crypto <-> TUN, timers and routing.

Session lifecycle (per peer, WireGuard's proven three-slot model):

    current   keypair used for sending
    previous  kept for receiving in-flight packets after a rekey
    next      (responder only) new keypair, promoted to current on the first
              authenticated packet from the initiator -- key confirmation, so
              the responder never sends on keys the initiator may not have.

Timers (protocol.py): the client re-handshakes proactively every
``rekey_interval`` seconds (fresh ML-KEM + ECDH ephemerals -> post-quantum
forward secrecy), keypairs die after 1.5x that, and silence after sending
data for KEEPALIVE_TIMEOUT + REKEY_TIMEOUT triggers a new handshake.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import random
import socket
import struct
import sys
import time
from collections import deque

from .handshake import HandshakeError, Initiator, Policy, Responder, ResponderHandshake, Result
from .pki import Certificate, Identity, TrustStore
from .protocol import (HALF_OPEN_TIMEOUT, HANDSHAKE_ATTEMPT_TIME, HEADER_LEN, KEEPALIVE_TIMEOUT,
                       MT_AUTH_I, MT_AUTH_R, MT_COOKIE, MT_INIT, MT_NAMES, MT_RESPONSE, MT_RETRY,
                       PT_DATA, PT_HANDSHAKE, REKEY_TIMEOUT, TAG_LEN, RateLimiter, Reassembler,
                       parse_hs)
from .session import Keypair, RouteTable, dst_addr, pad, src_addr, unpad
from .wire import DecodeError

log = logging.getLogger("pqvpn")
TICK = 0.5


def _norm_addr(addr) -> tuple[str, int]:
    """Collapse IPv4-mapped IPv6 so dual-stack sockets compare consistently."""
    ip = ipaddress.ip_address(addr[0].split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip), addr[1]


class Peer:
    def __init__(self, cert: Certificate, endpoint):
        self.cert = cert
        self.endpoint = endpoint
        self.current: Keypair | None = None
        self.previous: Keypair | None = None
        self.next: Keypair | None = None
        self.last_rx = 0.0
        self.last_tx = 0.0
        self.ack_due: float | None = None
        self.unanswered_since: float | None = None
        self.rx_bytes = self.tx_bytes = 0
        self.connected_since = time.monotonic()
        self.connected_wall = time.time()

    @property
    def name(self) -> str:
        return self.cert.subject

    def keypairs(self) -> list[Keypair]:
        return [k for k in (self.current, self.previous, self.next) if k is not None]


class BaseNode(asyncio.DatagramProtocol):
    def __init__(self, tun, mtu: int, rekey_interval: int):
        self.tun = tun
        self.mtu = mtu
        self.rekey_interval = rekey_interval
        self.reject_after = rekey_interval * 1.5
        self.transport: asyncio.DatagramTransport | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.indices: dict[int, tuple[Peer, Keypair]] = {}
        self.reasm = Reassembler()
        self._tick_handle: asyncio.TimerHandle | None = None
        self.closed = asyncio.Event()

    # -------------------------------------------------------------- asyncio glue
    def connection_made(self, transport) -> None:
        self.transport = transport

    def error_received(self, exc) -> None:  # ICMP errors etc.: UDP is best effort
        log.debug("socket error: %s", exc)

    def connection_lost(self, exc) -> None:
        self.closed.set()

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            addr = _norm_addr(addr)
            if not data:
                return
            if data[0] == PT_DATA:
                self.on_data(data, addr)
            elif data[0] == PT_HANDSHAKE:
                try:
                    hdr, payload = parse_hs(data)
                except DecodeError:
                    return
                self.on_handshake(hdr, payload, addr)
        except Exception:  # a single bad packet must never take the node down
            log.exception("error processing datagram from %s", addr)

    def on_tun_packets(self, packets: list[bytes]) -> None:
        for pkt in packets:
            try:
                self.route_outbound(pkt)
            except Exception:
                log.exception("error routing outbound packet")

    def start_timers(self) -> None:
        self.loop = asyncio.get_running_loop()
        self._schedule_tick()

    def _schedule_tick(self) -> None:
        self._tick_handle = self.loop.call_later(TICK, self._tick_wrapper)

    def _tick_wrapper(self) -> None:
        try:
            self.tick(time.monotonic())
        except Exception:
            log.exception("timer error")
        finally:
            if not self.closed.is_set():
                self._schedule_tick()

    def close(self) -> None:
        if self._tick_handle:
            self._tick_handle.cancel()
        if self.transport:
            self.transport.close()
        self.closed.set()

    # -------------------------------------------------------------- data plane
    def send_raw(self, datagrams: list[bytes], addr) -> None:
        if self.transport:
            for d in datagrams:
                self.transport.sendto(d, addr)

    def on_data(self, data: bytes, addr) -> None:
        if len(data) < HEADER_LEN + TAG_LEN:
            return
        entry = self.indices.get(struct.unpack_from(">I", data, 4)[0])
        if entry is None:
            return
        peer, kp = entry
        now = time.monotonic()
        if now - kp.created >= self.reject_after:
            return
        res = kp.decrypt(data)
        if res is None:
            return
        counter, pt = res
        peer.last_rx = now
        peer.unanswered_since = None
        if kp is peer.next:
            self._confirm(peer, kp)
        self.on_authenticated(peer, kp, addr, counter)
        if not pt:
            # The responder answers keepalives (the initiator never does, so there is no
            # ping-pong): this gives idle clients a liveness signal for dead-peer detection.
            if not kp.initiator and peer.ack_due is None:
                peer.ack_due = now
            return  # keepalive
        pkt = unpad(pt)
        if pkt is None or not self.inbound_allowed(peer, pkt):
            log.debug("dropped inner packet from %s (malformed or source not allowed)", peer.name)
            return
        peer.rx_bytes += len(pkt)
        if peer.ack_due is None:
            peer.ack_due = now
        self.tun.write(pkt)

    def send_to_peer(self, peer: Peer, pkt: bytes, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        kp = peer.current
        if kp is None or not kp.confirmed or now - kp.created >= self.reject_after:
            return False
        dgram = kp.encrypt(pad(pkt, self.mtu) if pkt else b"")
        if dgram is None:
            return False
        self.transport.sendto(dgram, peer.endpoint)
        peer.last_tx = now
        peer.ack_due = None
        if pkt:
            peer.tx_bytes += len(pkt)
        if (pkt or kp.initiator) and peer.unanswered_since is None:
            peer.unanswered_since = now  # expect an answer (data or the responder's keepalive ack)
        return True

    def install(self, peer: Peer, result: Result, now: float) -> Keypair:
        kp = Keypair(result, now)
        self.indices[kp.local_index] = (peer, kp)
        if result.initiator:
            self._drop(peer.previous)
            peer.previous, peer.current = peer.current, kp
        else:
            self._drop(peer.next)
            peer.next = kp
        return kp

    def _confirm(self, peer: Peer, kp: Keypair) -> None:
        kp.confirmed = True
        self._drop(peer.previous)
        peer.previous, peer.current, peer.next = peer.current, kp, None

    def _drop(self, kp: Keypair | None) -> None:
        if kp is not None:
            self.indices.pop(kp.local_index, None)

    def expire_keypairs(self, peer: Peer, now: float) -> None:
        for slot in ("current", "previous", "next"):
            kp = getattr(peer, slot)
            if kp is not None and (now - kp.created >= self.reject_after or kp.exhausted()):
                self._drop(kp)
                setattr(peer, slot, None)

    def keepalive_timers(self, peer: Peer, now: float) -> None:
        # Passive keepalive: acknowledge received data if we had nothing to say,
        # so the sender's dead-peer detection stays quiet.
        if peer.ack_due is not None and now - peer.ack_due >= KEEPALIVE_TIMEOUT:
            self.send_to_peer(peer, b"", now)

    # hooks
    def on_handshake(self, hdr, payload, addr) -> None:
        raise NotImplementedError

    def route_outbound(self, pkt: bytes) -> None:
        raise NotImplementedError

    def inbound_allowed(self, peer: Peer, pkt: bytes) -> bool:
        raise NotImplementedError

    def on_authenticated(self, peer: Peer, kp: Keypair, addr, counter: int) -> None:
        pass

    def tick(self, now: float) -> None:
        raise NotImplementedError


# ====================================================================== server

class ServerNode(BaseNode):
    def __init__(self, cfg, identity: Identity, trust: TrustStore, tun, access=None):
        super().__init__(tun, cfg.mtu, cfg.crypto.rekey_interval)
        self.cfg = cfg
        self.access = access  # portal.access.PortalAccess (account-based authorisation)
        self.policy = Policy(cfg.crypto.suites, cfg.crypto.psk)
        self.responder = Responder(identity, trust, self.policy, self.config_for)
        self.half_open: dict[int, ResponderHandshake] = {}
        self.init_index: dict[tuple, int] = {}
        self.peers: dict[str, Peer] = {}
        self.routes = RouteTable()
        self.rate = RateLimiter(cfg.handshake_rate, cfg.handshake_rate * 2)
        self.addresses = [ipaddress.ip_interface(a) for a in (cfg.addresses or identity.cert.addresses)]
        if not self.addresses:
            raise ValueError("server has no tunnel address (certificate or [tunnel] addresses)")
        self._last_status = 0.0

    # -------------------------------------------------------------- policy hook
    def config_for(self, cert: Certificate) -> dict:
        if cert.subject not in self.peers and len(self.peers) >= self.cfg.max_peers:
            raise HandshakeError("max_peers reached")
        overrides = {}
        if self.access is not None:
            overrides = self.access.authorize(cert)  # raises HandshakeError if the account is not allowed
        own = {a.ip for a in self.addresses}
        ifaces = []
        for net in cert.networks():
            if net.num_addresses != 1:
                continue
            host = net.network_address
            if host in own:
                raise HandshakeError(f"{cert.subject}: certificate claims the server's own address")
            srv = next((a for a in self.addresses if a.version == host.version and host in a.network), None)
            ifaces.append(f"{host}/{srv.network.prefixlen}" if srv else str(net))
        routes = self.cfg.push_routes or [str(a.network) for a in self.addresses]
        cfg = {"addresses": ifaces, "routes": routes, "dns": overrides.get("dns") or self.cfg.dns, "mtu": self.mtu,
               "rekey_interval": self.rekey_interval}
        if self.access is not None and self.access.url:
            cfg["portal"] = self.access.url
        return cfg

    # -------------------------------------------------------------- handshake
    def on_handshake(self, hdr, payload, addr) -> None:
        now = time.monotonic()
        if hdr.msg_type == MT_INIT:
            body = self.reasm.add((addr, MT_INIT, hdr.sender), hdr, payload, now)
            if body is not None:
                self._on_init(hdr, body, addr, now)
        elif hdr.msg_type == MT_AUTH_I:
            hs = self.half_open.get(hdr.receiver)
            if hs is None or hs.addr != addr:
                return
            try:
                flight, result = hs.on_auth_fragment(hdr, payload, now)
            except (HandshakeError, DecodeError) as exc:
                log.warning("handshake from %s:%d rejected: %s", *addr, exc)
                self._forget(hs)
                return
            self.send_raw(flight, addr)
            if result is not None:
                self._establish(result, addr, now)

    def _on_init(self, hdr, body: bytes, addr, now: float) -> None:
        key = (addr, hdr.sender)
        existing = self.half_open.get(self.init_index.get(key, 0))
        if existing is not None and existing.m1_digest == hashlib.sha256(body).digest():
            self.send_raw(existing.m2_flight, addr)  # our RESPONSE was lost
            return
        # Completed handshakes linger only to answer AUTH_I retransmissions;
        # load is measured by the ones still costing us state and CPU.
        pending = sum(1 for h in self.half_open.values() if h.m4_flight is None)
        under_load = self.cfg.always_require_cookie or pending >= self.cfg.cookie_threshold
        if under_load and not self.rate.allow(addr[0], now):
            return
        try:
            flight, hs = self.responder.on_init(hdr, body, addr, now, require_cookie=under_load,
                                                taken_indices=self._taken())
        except (HandshakeError, DecodeError) as exc:
            log.info("INIT from %s:%d rejected: %s", *addr, exc)
            return
        self.send_raw(flight, addr)
        if hs is not None:
            if len(self.half_open) >= 4 * max(self.cfg.cookie_threshold, 256):
                self._forget(next(iter(self.half_open.values())))
            self.half_open[hs.r_index] = hs
            self.init_index[key] = hs.r_index
            log.debug("INIT from %s:%d -> RESPONSE (%s)", *addr, hs.suite.name)

    def _taken(self) -> set[int]:
        return set(self.indices) | set(self.half_open)

    def _forget(self, hs: ResponderHandshake) -> None:
        self.half_open.pop(hs.r_index, None)
        key = (hs.addr, hs.i_index)
        if self.init_index.get(key) == hs.r_index:
            del self.init_index[key]

    def _establish(self, result: Result, addr, now: float) -> None:
        cert = result.peer_cert
        peer = self.peers.get(cert.subject)
        if peer is None:
            peer = self.peers[cert.subject] = Peer(cert, addr)
        elif peer.cert.encode() != cert.encode():
            self.routes.remove_value(peer)
            peer.cert = cert
        peer.endpoint = addr
        for net in cert.networks():
            old = self.routes.insert(net, peer)
            if old is not None and old is not peer:
                log.warning("address %s moved from %s to %s", net, old.name, peer.name)
        self.install(peer, result, now)
        log.info("peer %s authenticated from %s:%d [%s, %s] -> %s", cert.subject, *addr,
                 result.suite.name, cert.key_alg.name, ", ".join(cert.addresses))

    def disconnect(self, name: str, reason: str) -> None:
        peer = self.peers.pop(name, None)
        if peer is None:
            return
        for kp in peer.keypairs():
            self._drop(kp)
        peer.current = peer.previous = peer.next = None
        self.routes.remove_value(peer)
        log.warning("peer %s disconnected: %s", name, reason)

    # -------------------------------------------------------------- data
    def on_authenticated(self, peer: Peer, kp: Keypair, addr, counter: int) -> None:
        # Roaming: follow the client to a new address, but only on the
        # newest authenticated packet so replays cannot redirect traffic.
        if addr != peer.endpoint and kp is peer.current and counter == kp.replay.top:
            log.info("peer %s roamed %s:%d -> %s:%d", peer.name, *peer.endpoint, *addr)
            peer.endpoint = addr

    def route_outbound(self, pkt: bytes) -> None:
        peer = self.routes.lookup(dst_addr(pkt))
        if peer is not None:
            self.send_to_peer(peer, pkt)

    def inbound_allowed(self, peer: Peer, pkt: bytes) -> bool:
        return self.routes.lookup(src_addr(pkt)) is peer  # anti-spoofing

    # -------------------------------------------------------------- timers
    def tick(self, now: float) -> None:
        for hs in [h for h in self.half_open.values() if now - h.created > HALF_OPEN_TIMEOUT]:
            self._forget(hs)
        self.reasm.expire(now)
        for name, peer in list(self.peers.items()):
            self.expire_keypairs(peer, now)
            if not peer.keypairs():
                log.info("peer %s session expired", name)
                self.routes.remove_value(peer)
                del self.peers[name]
                continue
            self.keepalive_timers(peer, now)
        if self.access is not None:
            for name in self.access.sync(self.peers, now):
                self.disconnect(name, "account disabled or profile superseded in portal")
        if now - self._last_status > 60:
            self._last_status = now
            self.rate.prune(now)
            if self.peers:
                log.info("status: %d peer(s): %s", len(self.peers), ", ".join(
                    f"{p.name}(rx {p.rx_bytes} B, tx {p.tx_bytes} B)" for p in self.peers.values()))


# ====================================================================== client

class ClientNode(BaseNode):
    STAGED_MAX = 256

    def __init__(self, cfg, identity: Identity, trust: TrustStore, tun, endpoint, netcfg=None, on_state=None):
        super().__init__(tun, cfg.mtu, cfg.crypto.rekey_interval)
        self.on_state = on_state  # callable(state, info): e.g. the Windows tray icon
        self.state = "disconnected"
        self.cfg = cfg
        self.identity, self.trust = identity, trust
        self.policy = Policy(cfg.crypto.suites, cfg.crypto.psk)
        self.endpoint = _norm_addr(endpoint)
        self.netcfg = netcfg
        self.peer: Peer | None = None
        self.hs: Initiator | None = None
        self.hs_started = self.hs_sent = 0.0
        self.hs_rto = 1.0
        self.next_attempt = 0.0
        self.fail_backoff = 1.0
        self.staged: deque[bytes] = deque(maxlen=self.STAGED_MAX)
        self.configured = False
        self.connected = asyncio.Event()
        self.server_config: dict = {}

    def _set_state(self, state: str, **info) -> None:
        if state == self.state and state != "error":
            return
        self.state = state
        if self.on_state is not None:
            try:
                self.on_state(state, info)
            except Exception:
                log.exception("state callback failed")

    # -------------------------------------------------------------- handshake
    def start_handshake(self, now: float) -> None:
        if self.peer is None or self.peer.current is None:
            self._set_state("connecting" if self.state in ("disconnected", "connecting") else "reconnecting",
                            server=self.cfg.server_name, endpoint="%s:%d" % self.endpoint)
        self.hs = Initiator(self.identity, self.trust, self.policy, self.cfg.server_name,
                            set(self.indices))
        self.hs_started = now
        self.hs_rto = 1.0
        self._send_flight(now)
        log.debug("handshake started (index %08x, suite %s)", self.hs.index, self.hs.suite.name)

    def _send_flight(self, now: float) -> None:
        self.send_raw(self.hs.flight, self.endpoint)
        self.hs_sent = now

    def on_handshake(self, hdr, payload, addr) -> None:
        hs = self.hs
        if hs is None or addr != self.endpoint:
            return
        now = time.monotonic()
        mt = hdr.msg_type
        try:
            if mt in (MT_RESPONSE, MT_RETRY, MT_COOKIE):
                body = self.reasm.add((mt, hdr.sender, hdr.receiver), hdr, payload, now)
                if body is None:
                    return
                handler = {MT_RESPONSE: hs.on_response, MT_RETRY: hs.on_retry, MT_COOKIE: hs.on_cookie}[mt]
                if handler(hdr, body):
                    log.debug("%s received -> %s sent", MT_NAMES[mt], "AUTH_I" if mt == MT_RESPONSE else "INIT")
                    self.hs_rto = 1.0
                    self._send_flight(now)
            elif mt == MT_AUTH_R:
                result = hs.on_auth_fragment(hdr, payload, now)
                if result is not None:
                    self._established(result, now)
        except DecodeError:
            return  # unauthenticated garbage: ignore
        except HandshakeError as exc:
            log.error("handshake failed: %s", exc)
            self._set_state("error", message=str(exc))
            self.hs = None
            self.next_attempt = now + self.fail_backoff
            self.fail_backoff = min(self.fail_backoff * 2, 30.0)

    def _established(self, result: Result, now: float) -> None:
        self.hs = None
        self.fail_backoff = 1.0
        cfg = result.config or {}
        server_rekey = cfg.get("rekey_interval")
        if isinstance(server_rekey, int) and 30 <= server_rekey < self.rekey_interval:
            self.rekey_interval, self.reject_after = server_rekey, server_rekey * 1.5
        first = self.peer is None
        if first:
            self.peer = Peer(result.peer_cert, self.endpoint)
        self.peer.cert = result.peer_cert
        self.peer.endpoint = self.endpoint
        # A completed handshake proves the server is alive: forget liveness timers that
        # were started on the old (dead) session, or they would trigger a needless rekey.
        self.peer.unanswered_since = None
        self.install(self.peer, result, now)
        if not self.configured:
            self.server_config = cfg
            self._apply_config(cfg)
            self.configured = True
            log.info("connected to %s (%s) via %s; server key %s, tunnel address %s",
                     result.peer_cert.subject, "%s:%d" % self.endpoint, result.suite.name,
                     result.peer_cert.key_alg.name, ", ".join(cfg.get("addresses", [])) or "-")
        else:
            log.debug("rekeyed (%s)", result.suite.name)
        self.send_to_peer(self.peer, b"", now)  # key confirmation for the responder
        while self.staged:
            if not self.send_to_peer(self.peer, self.staged.popleft(), now):
                break
        self.connected.set()
        self._set_state("connected", server=result.peer_cert.subject, endpoint="%s:%d" % self.endpoint,
                        suite=result.suite.name, key_alg=result.peer_cert.key_alg.name,
                        address=", ".join(cfg.get("addresses", [])), portal=cfg.get("portal", ""))

    def _apply_config(self, cfg: dict) -> None:
        if self.netcfg is None:
            return
        addrs = [a for a in cfg.get("addresses", []) if isinstance(a, str)]
        routes = list(self.cfg.routes) or [r for r in cfg.get("routes", []) if isinstance(r, str)]
        dns = list(self.cfg.dns) or (cfg.get("dns", []) if self.cfg.use_server_dns else [])
        nc = self.netcfg
        nc.configure_interface(addrs, self.mtu)
        if self.cfg.full_tunnel:
            nc.pin_endpoint(self.endpoint[0])
            from .netcfg import FULL_V4, FULL_V6
            v6 = any(ipaddress.ip_interface(a).version == 6 for a in addrs)
            routes = routes + FULL_V4 + (FULL_V6 if v6 else [])
        nc.add_routes(routes)
        nc.set_dns([d for d in dns if isinstance(d, str)])

    async def _re_resolve(self) -> None:
        """Follow DNS changes of the server name (dynamic IPs, failover)."""
        try:
            ipaddress.ip_address(self.cfg.server_host)
            return
        except ValueError:
            pass
        try:
            infos = await self.loop.getaddrinfo(self.cfg.server_host, self.cfg.server_port,
                                                family=self.transport.get_extra_info("socket").family,
                                                type=socket.SOCK_DGRAM)
        except OSError as exc:
            log.warning("cannot resolve %s: %s", self.cfg.server_host, exc)
            return
        new = _norm_addr(infos[0][4]) if infos else None
        if new and new != self.endpoint:
            log.info("server %s now resolves to %s:%d", self.cfg.server_host, *new)
            self.endpoint = new

    # -------------------------------------------------------------- data
    def route_outbound(self, pkt: bytes) -> None:
        if self.peer is not None and self.send_to_peer(self.peer, pkt):
            return
        self.staged.append(pkt)
        now = time.monotonic()
        if self.hs is None and now >= self.next_attempt:
            self.start_handshake(now)

    def inbound_allowed(self, peer: Peer, pkt: bytes) -> bool:
        return src_addr(pkt) is not None  # the server is our gateway

    # -------------------------------------------------------------- timers
    def tick(self, now: float) -> None:
        self.reasm.expire(now)
        peer = self.peer
        if self.hs is not None:
            if now - self.hs_started > HANDSHAKE_ATTEMPT_TIME:
                log.warning("no answer from %s:%d, retrying with fresh keys", *self.endpoint)
                self.hs = None
                self.loop.create_task(self._re_resolve())
            elif now - self.hs_sent >= self.hs_rto:
                self.hs_rto = min(self.hs_rto * 2, 8.0) + random.uniform(0, 0.3)
                self._send_flight(now)
        if peer is not None:
            self.expire_keypairs(peer, now)
        cur = peer.current if peer else None
        dead = (peer is not None and peer.unanswered_since is not None
                and now - peer.unanswered_since > KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
        need = (cur is None or now - cur.created >= self.rekey_interval
                or cur.send_counter >= cur.rekey_after_messages or dead)
        if need and self.hs is None and now >= self.next_attempt:
            if dead:
                log.warning("server not responding; re-handshaking")
                peer.unanswered_since = None
                self._set_state("reconnecting", server=self.cfg.server_name)
            self.start_handshake(now)
        if peer is not None and cur is not None:
            self.keepalive_timers(peer, now)
            ka = self.cfg.persistent_keepalive
            if ka and now - peer.last_tx >= ka:
                self.send_to_peer(peer, b"", now)


# ====================================================================== runners

def _disable_windows_udp_reset(sock: socket.socket) -> None:
    """Stop ICMP port/net-unreachable from surfacing as WSAECONNRESET.

    Without this, one ICMP error (e.g. a client that went away) makes
    recvfrom() fail, and asyncio's Proactor UDP transport stops reading
    for good -- the node silently goes deaf.
    """
    import ctypes
    from ctypes import wintypes

    ws2 = ctypes.WinDLL("ws2_32")
    ws2.WSAIoctl.argtypes = [ctypes.c_size_t, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                             ctypes.c_void_p, ctypes.c_void_p]
    off, returned = wintypes.BOOL(False), wintypes.DWORD()
    for code in (0x9800000C, 0x9800000F):  # SIO_UDP_CONNRESET, SIO_UDP_NETRESET
        if ws2.WSAIoctl(sock.fileno(), code, ctypes.byref(off), ctypes.sizeof(off), None, 0,
                        ctypes.byref(returned), None, None) != 0:
            log.warning("WSAIoctl(0x%08x) failed; ICMP errors may stall the socket", code)


def make_udp_socket(host: str, port: int, family: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if sys.platform == "win32":
        _disable_windows_udp_reset(sock)
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # dual-stack
        except OSError:
            pass
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, 4 << 20)
        except OSError:
            pass
    sock.bind((host, port))
    sock.setblocking(False)
    return sock
