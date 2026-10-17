"""Summarise a libpcap capture (e.g. from `emulator -tcpdump`) without third-party packages.

    python research/pcap_summary.py capture.pcap [--since EPOCH] [--until EPOCH] [--vpn-port 51888]

Prints packet counts per (IP version, protocol, destination, destination port) for the outer, physical
traffic, so a leak test can show exactly what left the device outside the tunnel.  With --vpn-port it also
prints the size distribution of the encrypted VPN datagrams (for the traffic-analysis study).
Only headers are read; payloads are never printed.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import struct
import sys


def packets(path: str):
    """Yield (timestamp, ip_bytes) for Ethernet/raw-IP pcap files."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError("not a libpcap file")
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            data = f.read(incl)
            ts = sec + frac / (1e9 if nano else 1e6)
            if linktype == 1:  # Ethernet
                if len(data) < 14:
                    continue
                etype = struct.unpack(">H", data[12:14])[0]
                off = 14
                if etype == 0x8100:  # VLAN
                    etype = struct.unpack(">H", data[16:18])[0]
                    off = 18
                if etype not in (0x0800, 0x86DD):
                    continue
                yield ts, data[off:]
            elif linktype in (101, 228, 229):  # raw IP
                yield ts, data


def parse_ip(ip: bytes):
    """-> (version, proto, src, dst, sport, dport, ip_len, l4_payload_len) or None."""
    if not ip:
        return None
    v = ip[0] >> 4
    if v == 4 and len(ip) >= 20:
        ihl = (ip[0] & 15) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        proto = ip[9]
        src, dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        l4 = ip[ihl:]
    elif v == 6 and len(ip) >= 40:
        total = 40 + struct.unpack(">H", ip[4:6])[0]
        proto = ip[6]
        src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
        l4 = ip[40:]
    else:
        return None
    sport = dport = None
    payload = None
    if proto in (6, 17) and len(l4) >= 4:
        sport, dport = struct.unpack(">HH", l4[:4])
        if proto == 17 and len(l4) >= 8:
            payload = struct.unpack(">H", l4[4:6])[0] - 8
    return v, proto, src, dst, sport, dport, total, payload


PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def summarise(path: str, since: float | None = None, until: float | None = None, vpn_port: int | None = None):
    flows = collections.Counter()
    vpn_sizes = collections.Counter()
    first = last = None
    for ts, ip in packets(path):
        if (since is not None and ts < since) or (until is not None and ts > until):
            continue
        p = parse_ip(ip)
        if p is None:
            continue
        first = ts if first is None else first
        last = ts
        v, proto, src, dst, sport, dport, total, payload = p
        if vpn_port and proto == 17 and vpn_port in (sport, dport):
            vpn_sizes[("up" if dport == vpn_port else "down", payload)] += 1
            key = (v, "udp", "VPN tunnel", vpn_port)
        else:
            key = (v, PROTO.get(proto, str(proto)), dst, dport)
        flows[key] += 1
    return flows, vpn_sizes, first, last


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--since", type=float)
    ap.add_argument("--until", type=float)
    ap.add_argument("--vpn-port", type=int)
    a = ap.parse_args(argv)
    flows, sizes, first, last = summarise(a.pcap, a.since, a.until, a.vpn_port)
    print(f"window: {first} .. {last}")
    for (v, proto, dst, dport), n in sorted(flows.items(), key=lambda kv: -kv[1]):
        print(f"  IPv{v} {proto:6} -> {dst}:{dport if dport is not None else '-'}  {n} packets")
    if sizes:
        print("VPN datagram UDP payload sizes (direction, bytes: count):")
        for (d, s), n in sorted(sizes.items()):
            print(f"  {d:4} {s}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
