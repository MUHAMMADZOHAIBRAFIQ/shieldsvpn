"""Reproducible pqvpn performance benchmark (host side, no network or root needed).

    PQVPN_LIBCRYPTO=... python research/benchmarks/bench_dataplane.py [--quick] [--out results.json]
    PQVPN_LIBCRYPTO=... python research/benchmarks/bench_dataplane.py --transports [--out ab.json]

Measures, with the environment recorded next to every number:
  1. handshake CPU cost per suite (full INIT..AUTH_R exchange driven in memory, both sides on one core);
  2. per-packet cost of Keypair.encrypt / Keypair.decrypt (the data plane) at 64, 576 and 1400 bytes;
  3. end-to-end loopback throughput: MemoryTun -> ClientNode -> UDP 127.0.0.1 -> ServerNode -> MemoryTun.

Repeats every measurement and reports the median and the spread; nothing is extrapolated.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from pqvpn import pki  # noqa: E402
from pqvpn.crypto import ossl  # noqa: E402
from pqvpn.crypto.suites import SUITES_BY_NAME  # noqa: E402
from pqvpn.handshake import Initiator, Policy, Responder  # noqa: E402
from pqvpn.protocol import Reassembler, parse_hs  # noqa: E402
from pqvpn.runner import TestPKI, crypto_cfg, icmp_echo, loopback_pair, server_cfg  # noqa: E402
from pqvpn.session import Keypair, pad  # noqa: E402


def environment() -> dict:
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "openssl": ossl.version_string(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def summary(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"n": len(s), "median": statistics.median(s), "p10": s[len(s) // 10], "p90": s[(len(s) * 9) // 10],
            "min": s[0], "max": s[-1]}


def drive(ini: Initiator, rsp: Responder):
    """One complete handshake in memory; returns (initiator Result, responder Result)."""
    now = time.monotonic()
    addr = ("192.0.2.1", 4444)
    r = Reassembler()
    body = None
    for d in ini.flight:
        h, p = parse_hs(d)
        body = r.add(("i",), h, p, now) or body
    out, hs = rsp.on_init(h, body, addr, now, require_cookie=False, taken_indices=set())
    r = Reassembler()
    for d in out:
        rh, rp = parse_hs(d)
        body = r.add(("r",), rh, rp, now) or body
    m4, res_r = [], None
    for d in ini.on_response(rh, body):
        h, p = parse_hs(d)
        f, rr = hs.on_auth_fragment(h, p, now)
        m4 += f
        res_r = rr or res_r
    res_i = None
    for d in m4:
        h, p = parse_hs(d)
        res_i = ini.on_auth_fragment(h, p, now) or res_i
    assert res_i and res_r and res_i.send_key == res_r.recv_key
    return res_i, res_r


def bench_handshakes(tp: TestPKI, n: int) -> dict:
    srv = tp.identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"])
    cli = tp.identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
    out = {}
    for name, suite in SUITES_BY_NAME.items():
        times = []
        for _ in range(n):
            t0 = time.perf_counter()
            drive(Initiator(cli, tp.trust(), Policy((suite,)), "vpn.test"),
                  Responder(srv, tp.trust(), Policy((suite,)), lambda c: {"addresses": list(c.addresses)}))
            times.append((time.perf_counter() - t0) * 1000)
        out[name] = summary(times)
    return out


def bench_packets(tp: TestPKI, n: int) -> dict:
    srv = tp.identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"])
    cli = tp.identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
    out = {}
    for name in ("MLKEM768-X25519_CHACHA20POLY1305_SHA384", "MLKEM768-X25519_AES256GCM_SHA384"):
        suite = SUITES_BY_NAME[name]
        ri, rr = drive(Initiator(cli, tp.trust(), Policy((suite,)), "vpn.test"),
                       Responder(srv, tp.trust(), Policy((suite,)), lambda c: {}))
        tx, rx = Keypair(ri, 0), Keypair(rr, 0)
        for size in (64, 576, 1400):
            pkt = icmp_echo("10.66.0.2", "10.66.0.1", 1, os.urandom(size - 28))
            enc, dec = [], []
            for _rep in range(5):
                dgs = []
                t0 = time.perf_counter()
                for _ in range(n):
                    dgs.append(tx.encrypt(pad(pkt, 1420)))
                t1 = time.perf_counter()
                for d in dgs:
                    assert rx.decrypt(d) is not None
                t2 = time.perf_counter()
                enc.append((t1 - t0) / n * 1e6)
                dec.append((t2 - t1) / n * 1e6)
            out[f"{name} {size}B"] = {"encrypt_us": summary(enc), "decrypt_us": summary(dec),
                                      "encrypt_mbit_s_single_core": round(size * 8 / statistics.median(enc), 1)}
    return out


async def bench_loopback(tp: TestPKI, seconds: float, size: int, reps: int, burst: int = 64) -> dict:
    """Offered load: `burst` packets per event-loop turn, as fast as the sender can go (an overload test:
    it measures goodput = what arrives, plus the loss, not a paced loss-free rate)."""
    results = []
    for _ in range(reps):
        server, client, s_tun, c_tun = await loopback_pair(tp, server_cfg(crypto_cfg()))
        try:
            client.start_handshake(time.monotonic())
            await asyncio.wait_for(client.connected.wait(), 10)
            pkt = icmp_echo("10.66.0.2", "10.66.0.1", 1, os.urandom(size - 28))
            received = sent = 0
            t0 = time.perf_counter()
            deadline = t0 + seconds
            while time.perf_counter() < deadline:
                for _ in range(burst):
                    c_tun.inject(pkt)
                sent += burst
                await asyncio.sleep(0)
                while not s_tun.written.empty():
                    s_tun.written.get_nowait()
                    received += 1
            await asyncio.sleep(0.2)
            while not s_tun.written.empty():
                s_tun.written.get_nowait()
                received += 1
            elapsed = time.perf_counter() - t0
            results.append({"packets_per_s": received / elapsed, "mbit_s": received * size * 8 / elapsed / 1e6,
                            "loss": 1 - received / sent})
        finally:
            client.close()
            server.close()
            await asyncio.sleep(0.05)
    return {"packet_bytes": size, "seconds_per_run": seconds, "burst": burst,
            "loss": summary([r["loss"] for r in results]),
            "mbit_s": summary([r["mbit_s"] for r in results]),
            "packets_per_s": summary([r["packets_per_s"] for r in results])}


async def _asyncio_endpoint(protocol, sock):
    """A/B reference: asyncio's stock datagram transport (one datagram per loop iteration on selector loops)."""
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: protocol, sock=sock)
    return transport


async def bench_transports(tp: TestPKI, seconds: float, reps: int, bursts=(1, 8, 64)) -> dict:
    """Same loopback test, same process, with each UDP transport: isolates the receive-path change."""
    import pqvpn.runner as runner
    batched = runner.open_udp_endpoint
    out = {}
    for name, endpoint in (("asyncio", _asyncio_endpoint), ("batched", batched)):
        runner.open_udp_endpoint = endpoint
        try:
            out[name] = [await bench_loopback(tp, seconds, 1400, reps, b) for b in bursts]
        finally:
            runner.open_udp_endpoint = batched
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--transports", action="store_true", help="only the asyncio-vs-batched UDP receive A/B test")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    tp = TestPKI(ca_alg="SLH-DSA-SHA2-128s")
    res = {"environment": environment()}
    if a.transports:
        res["transports"] = asyncio.run(bench_transports(tp, 1.0 if a.quick else 2.0, 2 if a.quick else 3))
        for name, runs in res["transports"].items():
            for r in runs:
                print(f"{name:8s} burst {r['burst']:3d}: {r['mbit_s']['median']:7.1f} Mbit/s, "
                      f"loss {100 * r['loss']['median']:5.1f} %", file=sys.stderr)
        text = json.dumps(res, indent=2)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(text)
        return 0
    res["handshake_ms"] = bench_handshakes(tp, 5 if a.quick else 20)
    res["packet_crypto"] = bench_packets(tp, 2000 if a.quick else 10000)
    res["loopback"] = asyncio.run(bench_loopback(tp, 1.0 if a.quick else 3.0, 1400, 2 if a.quick else 5))
    text = json.dumps(res, indent=2)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
