#!/usr/bin/env python3
"""Load test: N simulated peers against one real VPN server process (docs/AUDIT-2026-11.md section 6).

    python3 research/benchmarks/bench_peers.py                      # 10, 50, 100, 250, 500, 1000 peers
    python3 research/benchmarks/bench_peers.py --peers 100 --rate 50 --size 1200
    python3 research/benchmarks/bench_peers.py --portal              # with PortalAccess + a SQLite device table
    python3 research/benchmarks/bench_peers.py --peers 1000 --profile 25   # cProfile of the server, top 25

What is REAL: the server process (ServerNode, the hybrid handshake, AEAD data plane, BatchedUdpTransport on Linux,
cryptokey routing) and, with --portal, PortalAccess against a SQLite database holding one registered Free device per
peer (handshake authorization, the 2-second sync that charges Free time and publishes live peers).

What is SIMULATED: the peers are pqvpn ClientNode instances with in-memory TUNs, run by load-generator processes on
the SAME host, talking over loopback UDP; the server's TUN is an echo device that reflects each inner packet back to
its sender (no kernel TUN, no NAT, no internet path).  So the numbers are the server's protocol and crypto work on
this machine, not internet throughput, not phone performance, and not a VPS's.  The benchmark PKI uses an ML-DSA-87
CA (fast to issue 1,000 certificates); production uses SLH-DSA, whose verification cost is paid once per certificate
and cached.  Handshake rate limits and cookies are raised so that 1,000 peers from 127.0.0.1 can connect quickly.

Per step it reports: connect time and handshake CPU on the server, idle phase (keepalives only) server CPU and
event-loop lag, traffic phase server CPU, packets per second, throughput, RSS, round-trip latency (load generator ->
server -> load generator), loss, reconnects, and peers still connected at the end.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import math
import multiprocessing as mp
import os
import platform
import random
import shutil
import socket
import statistics
import struct
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

SERVER_NET = ipaddress.ip_interface("10.80.0.1/16")  # room for 1,000+ peers
PEERS_PER_PROC = 250
SERVER_NAME = "vpn.bench"
PROBE = struct.Struct(">dQ")  # send time (perf_counter), sequence number


def _rss_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # peak, Linux reports KiB
    except ImportError:
        return float("nan")


def _cpu() -> float:
    t = os.times()
    return t.user + t.system


def _pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


# ====================================================================== PKI (parent)

def make_pki(n: int, portal: bool) -> dict:
    from pqvpn import pki
    from pqvpn.crypto import ossl
    from pqvpn.crypto.suites import sig_alg_by_name
    from pqvpn.portal import devices
    ca_alg, peer_alg = sig_alg_by_name("ML-DSA-87"), sig_alg_by_name("ML-DSA-65")
    ca_key = ca_alg.generate()
    ca = pki.self_sign_ca("Bench CA", ca_key, ca_alg, 2)

    def issue(role: int, subject: str, addrs: list[str]):
        k = peer_alg.generate()
        c = pki.issue(role=role, subject=subject, key_alg=peer_alg, public_key=peer_alg.public_bytes(k),
                      addresses=addrs, days=2, issuer_key=ca_key, issuer_alg=ca_alg, issuer_public=ca.public_key)
        return c.to_pem(), ossl.private_to_pem(k).decode()

    server = issue(pki.ROLE_SERVER, SERVER_NAME, [str(SERVER_NET)])
    peers = []
    base = int(SERVER_NET.ip)
    for i in range(n):
        ip = str(ipaddress.IPv4Address(base + 1 + i))
        subject = devices.new_subject() if portal else f"peer{i:05d}"
        cert_pem, key_pem = issue(pki.ROLE_CLIENT, subject, [f"{ip}/32"])
        peers.append((cert_pem, key_pem, ip, subject))
    return {"ca": ca.to_pem(), "server": server, "peers": peers}


def make_portal_db(path: str, peers: list) -> None:
    """One registered, enabled Free device per peer, with plenty of Free time (so nobody is cut off)."""
    from pqvpn import pki
    from pqvpn.portal.store import Store
    store = Store(path)
    now = int(time.time())
    rows = []
    for cert_pem, _key, ip, subject in peers:
        cert = pki.Certificate.from_pem(cert_pem)
        rows.append((subject, os.urandom(16).hex(), "android", ip, cert.serial_hex, cert.not_after, now, now,
                     10 ** 7))
    with store._db() as db:
        db.executemany("INSERT INTO vpn_devices (subject, token_hash, platform, vpn_ip, active_serial, cert_expires,"
                       " created_at, last_seen, free_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)


# ====================================================================== server process

def server_main(conn, ca_pem: str, server_pems: tuple, portal_db: str | None) -> None:
    from pqvpn import pki
    from pqvpn.crypto import ossl
    from pqvpn.crypto.suites import DEFAULT_PEER_SIG_ALGS
    from pqvpn.node import ServerNode, make_udp_socket, open_udp_endpoint
    from pqvpn.runner import crypto_cfg, server_cfg

    class EchoTun:
        """Reflects every inner IPv4 packet to its sender (src <-> dst), delivered in batches like a TUN read."""
        name, mtu = "echo", 1420

        def __init__(self):
            self.rx = self.tx = 0
            self.pending: list[bytes] = []
            self.loop = self.sink = None

        def start(self, loop, sink):
            self.loop, self.sink = loop, sink

        def write(self, pkt: bytes) -> None:
            self.rx += 1
            if len(pkt) >= 20 and pkt[0] >> 4 == 4:
                if not self.pending:
                    self.loop.call_soon(self.flush)
                self.pending.append(pkt[:12] + pkt[16:20] + pkt[12:16] + pkt[20:])

        def flush(self) -> None:
            batch, self.pending = self.pending, []
            self.tx += len(batch)
            self.sink(batch)

        def close(self) -> None:
            pass

    class BenchServer(ServerNode):
        established = 0

        def _establish(self, result, addr, now):
            self.established += 1
            super()._establish(result, addr, now)

    async def main():
        loop = asyncio.get_running_loop()
        ca = pki.Certificate.from_pem(ca_pem)
        identity = pki.Identity(pki.Certificate.from_pem(server_pems[0]), ossl.private_from_pem(server_pems[1].encode()))
        trust = pki.TrustStore([ca], peer_algs=DEFAULT_PEER_SIG_ALGS, ca_algs=("ML-DSA-87",))
        cfg = server_cfg(crypto_cfg(), addresses=[str(SERVER_NET)], max_peers=100000, cookie_threshold=100000,
                         handshake_rate=100000.0)
        access = None
        sync_times: list[float] = []
        if portal_db:
            from pqvpn.portal.access import PortalAccess
            access = PortalAccess(portal_db)
            real_sync = access.sync

            def timed_sync(peers, now):
                t0 = time.perf_counter()
                out = real_sync(peers, now)
                if access._last == now:  # it really ran (not skipped by the 2 s interval)
                    sync_times.append(time.perf_counter() - t0)
                return out
            access.sync = timed_sync
        tun = EchoTun()
        node = BenchServer(cfg, identity, trust, tun, access)
        transport = await open_udp_endpoint(node, make_udp_socket("127.0.0.1", 0, socket.AF_INET))
        tun.start(loop, node.on_tun_packets)
        node.start_timers()
        lags: list[float] = []

        def tick(expected: float) -> None:
            now = loop.time()
            lags.append(now - expected)
            loop.call_at(now + 0.02, tick, now + 0.02)
        loop.call_at(loop.time() + 0.02, tick, loop.time() + 0.02)
        profiler = None
        stop = asyncio.Event()

        def snapshot() -> dict:
            nonlocal lags
            sample, lags = lags, []
            st, sync_times[:] = list(sync_times), []
            return {"t": time.perf_counter(), "cpu": _cpu(), "rss_mb": _rss_mb(), "rx": tun.rx, "tx": tun.tx,
                    "peers": len(node.peers), "established": node.established,
                    "lag_p50": _pct(sample, 0.5), "lag_p99": _pct(sample, 0.99), "lag_max": max(sample, default=0),
                    "sync_n": len(st), "sync_mean": statistics.fmean(st) if st else 0.0,
                    "sync_max": max(st, default=0.0)}

        async def handle(cmd):
            nonlocal profiler
            if cmd[0] == "stats":
                return snapshot()
            if cmd[0] == "profile_start":
                import cProfile
                profiler = cProfile.Profile()
                profiler.enable()
                return {}
            if cmd[0] == "profile_stop":
                import io
                import pstats
                profiler.disable()
                out = io.StringIO()
                pstats.Stats(profiler, stream=out).sort_stats("tottime").print_stats(cmd[1])
                return {"profile": out.getvalue()}
            if cmd[0] == "stop":
                stop.set()
                return {}
            return {"error": "unknown"}

        def control():
            while True:
                try:
                    cmd = conn.recv()
                except EOFError:
                    loop.call_soon_threadsafe(stop.set)
                    return
                conn.send(asyncio.run_coroutine_threadsafe(handle(cmd), loop).result())
                if cmd[0] == "stop":
                    return
        conn.send({"port": transport.get_extra_info("sockname")[1], "transport": type(transport).__name__,
                   "loop": type(loop).__name__})
        threading.Thread(target=control, daemon=True).start()
        await stop.wait()
        node.close()

    asyncio.run(main())


# ====================================================================== load-generator process

def loadgen_main(conn, ca_pem: str, peers: list, port: int, ramp: float) -> None:
    from pqvpn import pki
    from pqvpn.crypto import ossl
    from pqvpn.crypto.suites import DEFAULT_PEER_SIG_ALGS
    from pqvpn.node import ClientNode, make_udp_socket, open_udp_endpoint
    from pqvpn.runner import client_cfg, crypto_cfg

    stats = {"recv": 0, "rtt": [], "reconnects": 0}

    class ProbeTun:
        name, mtu = "probe", 1420

        def __init__(self):
            self.sink = None

        def start(self, loop, sink):
            self.sink = sink

        def write(self, pkt: bytes) -> None:
            if len(pkt) >= 20 + PROBE.size:
                sent, _seq = PROBE.unpack_from(pkt, 20)
                stats["recv"] += 1
                rtt = stats["rtt"]
                if len(rtt) < 50000 or random.random() < 0.05:
                    rtt.append(time.perf_counter() - sent)

        def close(self) -> None:
            pass

    def on_state(state, _info):
        if state in ("reconnecting", "error"):
            stats["reconnects"] += 1

    async def main():
        loop = asyncio.get_running_loop()
        trust = pki.TrustStore([pki.Certificate.from_pem(ca_pem)], peer_algs=DEFAULT_PEER_SIG_ALGS,
                               ca_algs=("ML-DSA-87",))
        nodes = []
        for cert_pem, key_pem, ip, _subject in peers:
            ident = pki.Identity(pki.Certificate.from_pem(cert_pem), ossl.private_from_pem(key_pem.encode()))
            tun = ProbeTun()
            node = ClientNode(client_cfg(crypto_cfg(), port, server_name=SERVER_NAME, persistent_keepalive=25),
                              ident, trust, tun, ("127.0.0.1", port), on_state=on_state)
            sock = make_udp_socket("127.0.0.1", 0, socket.AF_INET)
            # make_udp_socket asks for 4 MiB buffers (for single-flow throughput). With hundreds of peers per
            # process that is ~1 GiB of socket memory and can stall or OOM the generator; a client flow is light, so
            # cap it small here. This is benchmark-only tuning; the server keeps its large buffer.
            for _opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, _opt, 1 << 18)
                except OSError:
                    pass
            await open_udp_endpoint(node, sock)
            tun.start(loop, node.on_tun_packets)
            src = ipaddress.IPv4Address(ip).packed
            nodes.append((node, tun, src))

        async def connect(timeout: float) -> dict:
            t0 = time.perf_counter()
            for node, _tun, _src in nodes:
                # Timers start with the handshake: a ClientNode's first tick would otherwise start every peer's
                # handshake at once and ignore the ramp.
                node.start_handshake(time.monotonic())
                node.start_timers()
                await asyncio.sleep(1 / ramp)
            done = lambda: sum(1 for n, _, _ in nodes if n.connected.is_set())  # noqa: E731
            deadline, nextlog = time.perf_counter() + timeout, 0.0
            while time.perf_counter() < deadline and done() < len(nodes):
                if time.perf_counter() >= nextlog:
                    print(f"[gen {os.getpid()}] connected {done()}/{len(nodes)}", file=sys.stderr, flush=True)
                    nextlog = time.perf_counter() + 2.0
                await asyncio.sleep(0.05)
            return {"connected": done(), "seconds": time.perf_counter() - t0}

        async def traffic(rate: float, size: int, seconds: float) -> dict:
            stats["recv"], stats["rtt"], stats["reconnects"] = 0, [], 0
            body = max(size - 20, PROBE.size)
            dst = SERVER_NET.ip.packed
            pad = bytes(body - PROBE.size)
            sent, seq = 0, 0
            credit = [random.random() for _ in nodes]  # spread the first packets
            cpu0, t0 = _cpu(), time.perf_counter()
            last = t0
            while time.perf_counter() - t0 < seconds:
                await asyncio.sleep(0.01)
                now = time.perf_counter()
                add = rate * (now - last)
                last = now
                if rate <= 0:
                    continue
                for i, (node, tun, src) in enumerate(nodes):
                    credit[i] += add
                    while credit[i] >= 1:
                        credit[i] -= 1
                        seq += 1
                        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + body, seq & 0xFFFF, 0, 64, 17, 0, src, dst)
                        tun.sink([hdr + PROBE.pack(time.perf_counter(), seq) + pad])
                        sent += 1
            await asyncio.sleep(1.0)  # let the last echoes arrive
            rtt = stats["rtt"]
            return {"sent": sent, "recv": stats["recv"], "cpu": _cpu() - cpu0, "wall": time.perf_counter() - t0,
                    "rtt_p50": _pct(rtt, 0.5), "rtt_p95": _pct(rtt, 0.95), "rtt_p99": _pct(rtt, 0.99),
                    "rtt_max": max(rtt, default=float("nan")), "reconnects": stats["reconnects"],
                    "connected_end": sum(1 for n, _, _ in nodes if n.peer and n.peer.current)}

        conn.send({"ready": len(nodes)})
        while True:
            cmd = await loop.run_in_executor(None, conn.recv)
            if cmd[0] == "connect":
                conn.send(await connect(cmd[1]))
            elif cmd[0] == "traffic":
                conn.send(await traffic(*cmd[1:]))
            elif cmd[0] == "stop":
                for n, _, _ in nodes:
                    n.close()
                conn.send({})
                return

    asyncio.run(main())


# ====================================================================== orchestration

def _progress(*parts) -> None:
    print("#", time.strftime("%H:%M:%S"), *parts, file=sys.stderr, flush=True)


class StepTimeout(Exception):
    pass


def _recv(conn, timeout: float, what: str):
    """Receive one object within ``timeout`` seconds, or raise StepTimeout (so a stuck child never hangs the run)."""
    if not conn.poll(timeout):
        raise StepTimeout(f"no reply to {what} within {timeout:.0f}s")
    return conn.recv()


def _rpc_all(conns, cmd, timeout: float) -> list:
    """Send ``cmd`` to every generator, then collect all replies within ``timeout`` total."""
    for c in conns:
        c.send(cmd)
    deadline, out = time.monotonic() + timeout, []
    for c in conns:
        out.append(_recv(c, max(0.1, deadline - time.monotonic()), cmd[0]))
    return out


def _teardown(procs) -> None:
    for p in procs:
        if p.is_alive():
            p.terminate()
    for p in procs:
        p.join(5)
        if p.is_alive():
            p.kill()
            p.join(2)


def run_step(n: int, args, material: dict) -> dict:
    ctx = mp.get_context("spawn")
    peers = material["peers"][:n]
    tmp = tempfile.mkdtemp(prefix="pqvpn-bench-")
    db = None
    if args.portal:
        db = os.path.join(tmp, "portal.db")
        make_portal_db(db, peers)
    s_parent, s_child = ctx.Pipe()
    server = ctx.Process(target=server_main, args=(s_child, material["ca"], material["server"], db), daemon=True)
    server.start()
    # At most 250 peers per load generator, and spread larger runs over --procs so the generators are not the limit.
    nproc = max(math.ceil(n / PEERS_PER_PROC), min(args.procs, max(1, n // 50)))
    chunks = [peers[i::nproc] for i in range(nproc)]
    gens, gconns, procs = [], [], [server]
    try:
        info = _recv(s_parent, 60, "server start")
        _progress(f"{n} peers: server up ({info['loop']}, {info['transport']})")
        for chunk in chunks:
            a, b = ctx.Pipe()
            p = ctx.Process(target=loadgen_main, args=(b, material["ca"], chunk, info["port"], args.ramp / nproc),
                            daemon=True)
            p.start()
            gens.append(p)
            gconns.append(a)
            procs.append(p)
        ready_deadline = time.monotonic() + max(60.0, n * 0.2)   # generators build their nodes (keys, sockets) first
        for c in gconns:
            _recv(c, max(0.1, ready_deadline - time.monotonic()), "generator ready")
        _progress(f"{n} peers: {nproc} generator(s) ready; connecting (deadline {args.connect_timeout:.0f}s)")

        s_parent.send(("stats",))
        before = _recv(s_parent, 30, "stats")
        conn_res = _rpc_all(gconns, ("connect", args.connect_timeout), args.connect_timeout + 30)
        s_parent.send(("stats",))
        after_connect = _recv(s_parent, 30, "stats")
        connected = sum(r["connected"] for r in conn_res)
        _progress(f"{n} peers: {connected}/{n} connected, server established {after_connect['established']}")

        time.sleep(1.0)
        s_parent.send(("stats",))
        idle0 = _recv(s_parent, 30, "stats")
        time.sleep(args.idle)
        s_parent.send(("stats",))
        idle1 = _recv(s_parent, 30, "stats")

        if args.profile:
            s_parent.send(("profile_start",))
            _recv(s_parent, 30, "profile_start")
        # Server measurements cover exactly the traffic window (the generators then wait 1 s for the last echoes).
        for c in gconns:
            c.send(("traffic", args.rate, args.size, args.duration))
        s_parent.send(("stats",))
        t0s = _recv(s_parent, 30, "stats")
        time.sleep(args.duration)
        s_parent.send(("stats",))
        t1 = _recv(s_parent, 30, "stats")
        traffic = [_recv(c, args.duration + 30, "traffic") for c in gconns]
        profile = None
        if args.profile:
            s_parent.send(("profile_stop", args.profile))
            profile = _recv(s_parent, 60, "profile_stop")["profile"]
        # All measurements are now collected. Skip a graceful "stop" RPC (its reply was unreliable at some sizes and
        # it measures nothing) and just terminate the processes.
    except StepTimeout as exc:
        _progress(f"{n} peers: TIMED OUT -- {exc}")
        _teardown(procs)
        shutil.rmtree(tmp, ignore_errors=True)
        return {"peers": n, "status": "timeout", "detail": str(exc), "loadgen_procs": nproc}
    _teardown(procs)
    shutil.rmtree(tmp, ignore_errors=True)

    wall = t1["t"] - t0s["t"]
    sent = sum(r["sent"] for r in traffic)
    recv = sum(r["recv"] for r in traffic)
    rtts = [r for r in traffic]
    echo_pps = (t1["tx"] - t0s["tx"]) / wall
    hs_cpu_ms = (after_connect["cpu"] - before["cpu"]) / max(1, after_connect["established"]) * 1000
    result = {
        "peers": n, "connected": connected, "connect_s": round(max(r["seconds"] for r in conn_res), 2),
        "server_hs_cpu_ms": round(hs_cpu_ms, 2),
        "idle_cpu_pct": round((idle1["cpu"] - idle0["cpu"]) / (idle1["t"] - idle0["t"]) * 100, 1),
        "idle_lag_p99_ms": round(idle1["lag_p99"] * 1000, 1), "idle_lag_max_ms": round(idle1["lag_max"] * 1000, 1),
        "sync_mean_ms": round(idle1["sync_mean"] * 1000, 1), "sync_max_ms": round(idle1["sync_max"] * 1000, 1),
        "offered_pps": round(n * args.rate), "server_echo_pps": round(echo_pps),
        "throughput_mbit_each_way": round(echo_pps * args.size * 8 / 1e6, 1),
        "traffic_cpu_pct": round((t1["cpu"] - t0s["cpu"]) / wall * 100, 1),
        "traffic_lag_p99_ms": round(t1["lag_p99"] * 1000, 1), "traffic_lag_max_ms": round(t1["lag_max"] * 1000, 1),
        "rss_mb": round(t1["rss_mb"], 1),
        "loss_pct": round((1 - recv / sent) * 100, 2) if sent else 0.0,
        "rtt_p50_ms": round(statistics.median(r["rtt_p50"] for r in rtts) * 1000, 2),
        "rtt_p99_ms": round(max(r["rtt_p99"] for r in rtts) * 1000, 2),
        "reconnects": sum(r["reconnects"] for r in traffic),
        "connected_end": sum(r["connected_end"] for r in traffic),
        "loadgen_cpu_pct_max": round(max(r["cpu"] / r["wall"] for r in traffic) * 100, 1),
        "loadgen_procs": nproc, "status": "ok",
    }
    if profile:
        result["profile"] = profile
    return result


def environment() -> dict:
    from pqvpn.crypto import ossl
    return {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
            "cpus": os.cpu_count(), "openssl": ossl.version_string(), "date": time.strftime("%Y-%m-%d %H:%M")}


COLUMNS = [("peers", "peers"), ("connected", "conn"), ("connect_s", "conn s"), ("server_hs_cpu_ms", "hs ms"),
           ("idle_cpu_pct", "idle cpu%"), ("idle_lag_max_ms", "idle lag ms"), ("sync_max_ms", "sync ms"),
           ("offered_pps", "offered pps"), ("server_echo_pps", "echo pps"), ("throughput_mbit_each_way", "Mbit/s"),
           ("traffic_cpu_pct", "cpu%"), ("traffic_lag_p99_ms", "lag p99"), ("rss_mb", "RSS MB"),
           ("loss_pct", "loss%"), ("rtt_p50_ms", "rtt p50"), ("rtt_p99_ms", "rtt p99"), ("reconnects", "reconn"),
           ("loadgen_cpu_pct_max", "gen cpu%")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--peers", type=int, nargs="+", default=[10, 50, 100, 250, 500, 1000])
    ap.add_argument("--rate", type=float, default=10.0, help="packets per second per peer (default 10)")
    ap.add_argument("--size", type=int, default=600, help="inner IP packet size in bytes (default 600)")
    ap.add_argument("--duration", type=float, default=20.0, help="traffic phase seconds")
    ap.add_argument("--idle", type=float, default=10.0, help="keepalive-only phase seconds")
    ap.add_argument("--ramp", type=float, default=200.0, help="new handshakes per second while connecting")
    ap.add_argument("--connect-timeout", type=float, default=60.0, help="seconds to wait for all peers to connect")
    ap.add_argument("--procs", type=int, default=4, help="load-generator processes (at most 250 peers each)")
    ap.add_argument("--portal", action="store_true", help="server with PortalAccess and a SQLite device table")
    ap.add_argument("--profile", type=int, default=0, help="print the top N server functions (cProfile)")
    ap.add_argument("--out", help="write JSON results here")
    args = ap.parse_args(argv)
    env = environment()
    print(f"# {env}\n# rate {args.rate} pps/peer x {args.size} B, portal={args.portal}; SIMULATED peers on this "
          f"host, echo TUN on the server (see the module docstring)", flush=True)
    t0 = time.perf_counter()
    material = make_pki(max(args.peers), args.portal)
    print(f"# PKI for {max(args.peers)} peers in {time.perf_counter() - t0:.1f} s", flush=True)
    print(" | ".join(h for _k, h in COLUMNS), flush=True)
    results = []
    for n in args.peers:
        r = run_step(n, args, material)
        results.append(r)
        if r.get("status") == "timeout":
            print(f"{n} | TIMEOUT: {r['detail']}", flush=True)
        else:
            print(" | ".join(str(r.get(k, "-")) for k, _h in COLUMNS), flush=True)
        if r.get("profile"):
            print(r["profile"])
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"environment": env, "args": vars(args), "results": results}, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
