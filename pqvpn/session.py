"""Data plane: transport keypairs, anti-replay and inner-packet helpers.

Transport datagram (WireGuard-style, header authenticated as AAD):

    0      1               4               8                              16
    +------+---------------+---------------+-------------------------------+
    | 0x04 |   reserved    | receiver idx  |        counter (u64 BE)       |
    +------+---------------+---------------+-------------------------------+
    |      AEAD(key_dir, nonce = 0^32 || counter, aad = header, IP packet)  |
    +----------------------------------------------------------------------+

Each direction has its own key, counters never repeat (the session is retired
long before the counter space is exhausted), and the receiver enforces a
2048-packet sliding replay window (RFC 6479) *after* authentication.
"""

from __future__ import annotations

import ipaddress
import struct

from .crypto import ossl
from .handshake import Result
from .protocol import DATA_HEADER, HEADER_LEN, PT_DATA, TAG_LEN

_NONCE_PREFIX = bytes(4)


class ReplayWindow:
    SIZE = 2048

    __slots__ = ("top", "bitmap", "limit")

    def __init__(self, limit: int):
        self.top = -1
        self.bitmap = 0
        self.limit = limit

    def check(self, n: int) -> bool:
        if n >= self.limit:
            return False
        if n > self.top:
            return True
        diff = self.top - n
        return diff < self.SIZE and not (self.bitmap >> diff) & 1

    def update(self, n: int) -> None:
        if n > self.top:
            shift = n - self.top
            self.bitmap = 1 if shift >= self.SIZE else ((self.bitmap << shift) | 1) & ((1 << self.SIZE) - 1)
            self.top = n
        else:
            self.bitmap |= 1 << (self.top - n)


class Keypair:
    """One established session (both directions)."""

    def __init__(self, result: Result, now: float):
        suite = result.suite
        self.suite = suite
        self.local_index = result.local_index
        self.remote_index = result.remote_index
        self.initiator = result.initiator
        self.created = now
        self.rekey_after_messages = suite.rekey_after_messages
        self.reject_after_messages = min(2 * suite.rekey_after_messages, (1 << 64) - (1 << 13) - 1)
        self._send = ossl.AEAD(suite.aead, result.send_key, True)
        self._recv = ossl.AEAD(suite.aead, result.recv_key, False)
        self.send_counter = 0
        self.replay = ReplayWindow(self.reject_after_messages)
        # The responder may not send on a new session until the initiator has
        # demonstrated it holds the keys (first authenticated packet).
        self.confirmed = result.initiator

    def exhausted(self) -> bool:
        return self.send_counter >= self.reject_after_messages

    def encrypt(self, plaintext: bytes) -> bytes | None:
        n = self.send_counter
        if n >= self.reject_after_messages:
            return None
        self.send_counter = n + 1
        header = DATA_HEADER.pack(PT_DATA, self.remote_index, n)
        return header + self._send.seal(_NONCE_PREFIX + struct.pack(">Q", n), header, plaintext)

    def decrypt(self, datagram: bytes) -> tuple[int, bytes] | None:
        if len(datagram) < HEADER_LEN + TAG_LEN:
            return None
        header = bytes(datagram[:HEADER_LEN])
        _pt, _idx, n = DATA_HEADER.unpack(header)
        if not self.replay.check(n):
            return None
        pt = self._recv.open(_NONCE_PREFIX + struct.pack(">Q", n), header, bytes(datagram[HEADER_LEN:]))
        if pt is None:
            return None
        self.replay.update(n)
        return n, pt


# ------------------------------------------------------------------ IP helpers

def pad(packet: bytes, mtu: int) -> bytes:
    """Pad to a 16-byte multiple (never beyond MTU) to blunt length analysis."""
    n = len(packet)
    target = min(-(-n // 16) * 16, max(mtu, n))
    return packet + bytes(target - n)


def unpad(plaintext: bytes) -> bytes | None:
    """Recover the IP packet using its own length field; None if malformed."""
    if not plaintext:
        return None
    v = plaintext[0] >> 4
    if v == 4 and len(plaintext) >= 20:
        n = struct.unpack_from(">H", plaintext, 2)[0]
    elif v == 6 and len(plaintext) >= 40:
        n = 40 + struct.unpack_from(">H", plaintext, 4)[0]
    else:
        return None
    if n > len(plaintext) or n < 20:
        return None
    return plaintext[:n]


def dst_addr(packet: bytes) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    v = packet[0] >> 4 if packet else 0
    if v == 4 and len(packet) >= 20:
        return ipaddress.IPv4Address(packet[16:20])
    if v == 6 and len(packet) >= 40:
        return ipaddress.IPv6Address(packet[24:40])
    return None


def src_addr(packet: bytes) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    v = packet[0] >> 4 if packet else 0
    if v == 4 and len(packet) >= 20:
        return ipaddress.IPv4Address(packet[12:16])
    if v == 6 and len(packet) >= 40:
        return ipaddress.IPv6Address(packet[8:24])
    return None


class RouteTable:
    """Longest-prefix-match table: network -> value (cryptokey routing)."""

    def __init__(self):
        self._by_len: dict[tuple[int, int], dict[int, object]] = {}
        self._lens: dict[int, list[int]] = {4: [], 6: []}

    def insert(self, net, value) -> object | None:
        key = (net.version, net.prefixlen)
        bucket = self._by_len.setdefault(key, {})
        if net.prefixlen not in self._lens[net.version]:
            self._lens[net.version] = sorted(self._lens[net.version] + [net.prefixlen], reverse=True)
        old = bucket.get(int(net.network_address))
        bucket[int(net.network_address)] = value
        return old

    def remove_value(self, value) -> None:
        for bucket in self._by_len.values():
            for k in [k for k, v in bucket.items() if v is value]:
                del bucket[k]

    def lookup(self, addr):
        if addr is None:
            return None
        bits = 32 if addr.version == 4 else 128
        a = int(addr)
        for plen in self._lens[addr.version]:
            bucket = self._by_len.get((addr.version, plen))
            if bucket:
                v = bucket.get(a & (((1 << plen) - 1) << (bits - plen)))
                if v is not None:
                    return v
        return None
