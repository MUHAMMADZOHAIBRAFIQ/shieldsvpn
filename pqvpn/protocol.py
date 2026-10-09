"""Wire constants, datagram headers, handshake fragmentation and DoS defences.

Post-quantum handshake messages are large (an ML-KEM-768 key share is 1184
bytes, an ML-DSA-65 signature 3309, an SLH-DSA-192s CA signature 16224).
Relying on IP fragmentation would make the VPN fail on the many paths that
drop fragments, so -- as IKEv2 does in RFC 7383 -- handshake messages are
fragmented at the application layer into datagrams that fit the IPv6 minimum
MTU (<= 1232 bytes of UDP payload).  Encrypted handshake messages are
encrypted *per fragment* so forged fragments are discarded individually
instead of poisoning reassembly.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
import time
from dataclasses import dataclass

from .wire import DecodeError

VERSION = 1

# packet types (first byte of every UDP datagram)
PT_HANDSHAKE = 0x01
PT_DATA = 0x04

# handshake message types
MT_INIT = 1       # I -> R  plaintext: nonce, offered suites, key shares, cookie
MT_RESPONSE = 2   # R -> I  plaintext: nonce, chosen suite, KEM ciphertexts / ECDH shares
MT_AUTH_I = 3     # I -> R  encrypted: certificate, signature, finished
MT_AUTH_R = 4     # R -> I  encrypted: certificate, signature, tunnel config, finished
MT_RETRY = 5      # R -> I  plaintext: "use suite X" (TLS 1.3 HelloRetryRequest)
MT_COOKIE = 6     # R -> I  plaintext: return-routability cookie (IKEv2 COOKIE)
MT_NAMES = {MT_INIT: "INIT", MT_RESPONSE: "RESPONSE", MT_AUTH_I: "AUTH_I",
            MT_AUTH_R: "AUTH_R", MT_RETRY: "RETRY", MT_COOKIE: "COOKIE"}
ENCRYPTED_MTS = (MT_AUTH_I, MT_AUTH_R)

# type | version | msg type | frag idx | frag count | reserved | total len | sender idx | receiver idx
HS_HEADER = struct.Struct(">BBBBBBHII")
# type | reserved[3] | receiver idx | counter
DATA_HEADER = struct.Struct(">B3xIQ")
HEADER_LEN = 16
TAG_LEN = 16
CHUNK = 1184               # 16 hdr + 1184 + 16 tag = 1216 <= 1232 (IPv6 min MTU - 48)
MAX_FRAGMENTS = 64
MAX_MESSAGE = 0xFFFF
DATA_OVERHEAD = HEADER_LEN + TAG_LEN

# timers (seconds) -- WireGuard's well-tested values where applicable
REKEY_AFTER_TIME = 120
REJECT_AFTER_TIME = 180
KEEPALIVE_TIMEOUT = 10
REKEY_TIMEOUT = 5
HANDSHAKE_ATTEMPT_TIME = 30   # fresh ephemeral keys after this long
HALF_OPEN_TIMEOUT = 15
REASSEMBLY_TIMEOUT = 10


@dataclass(frozen=True)
class HsHeader:
    msg_type: int
    frag_idx: int
    frag_count: int
    total_len: int
    sender: int
    receiver: int
    raw: bytes

    def expected_chunk_len(self) -> int:
        if self.frag_idx < self.frag_count - 1:
            return CHUNK
        return self.total_len - CHUNK * (self.frag_count - 1)


def parse_hs(datagram: bytes) -> tuple[HsHeader, bytes]:
    if len(datagram) < HEADER_LEN:
        raise DecodeError("short handshake datagram")
    pt, ver, mt, idx, cnt, rsv, total, snd, rcv = HS_HEADER.unpack_from(datagram)
    if pt != PT_HANDSHAKE or ver != VERSION or rsv != 0 or mt not in MT_NAMES:
        raise DecodeError("bad handshake header")
    if not 1 <= cnt <= MAX_FRAGMENTS or idx >= cnt or cnt != max(1, math.ceil(total / CHUNK)):
        raise DecodeError("inconsistent fragmentation")
    hdr = HsHeader(mt, idx, cnt, total, snd, rcv, bytes(datagram[:HEADER_LEN]))
    payload = bytes(datagram[HEADER_LEN:])
    want = hdr.expected_chunk_len() + (TAG_LEN if mt in ENCRYPTED_MTS else 0)
    if len(payload) != want:
        raise DecodeError("fragment length mismatch")
    return hdr, payload


def fragment_nonce(msg_type: int, idx: int) -> bytes:
    return bytes(10) + bytes([msg_type, idx])


def fragment(msg_type: int, sender: int, receiver: int, body: bytes, seal=None) -> list[bytes]:
    """Split a handshake message into datagrams.

    ``seal(nonce, aad, chunk)`` encrypts each fragment for encrypted messages.
    Callers MUST cache and resend the returned datagrams verbatim: rebuilding
    a message (e.g. re-signing) would reuse a (key, nonce) pair.
    """
    total = len(body)
    if total > MAX_MESSAGE:
        raise ValueError("handshake message too large")
    count = max(1, math.ceil(total / CHUNK))
    if count > MAX_FRAGMENTS:
        raise ValueError("too many fragments")
    out = []
    for i in range(count):
        chunk = body[i * CHUNK:(i + 1) * CHUNK]
        hdr = HS_HEADER.pack(PT_HANDSHAKE, VERSION, msg_type, i, count, 0, total, sender, receiver)
        out.append(hdr + (seal(fragment_nonce(msg_type, i), hdr, chunk) if seal else chunk))
    return out


class Reassembly:
    __slots__ = ("count", "total", "chunks", "created", "nbytes")

    def __init__(self, hdr: HsHeader, now: float):
        self.count, self.total = hdr.frag_count, hdr.total_len
        self.chunks: dict[int, bytes] = {}
        self.created = now
        self.nbytes = 0

    def add(self, hdr: HsHeader, chunk: bytes) -> bytes | None:
        if hdr.frag_count != self.count or hdr.total_len != self.total:
            return None
        if hdr.frag_idx not in self.chunks:  # first copy wins
            self.chunks[hdr.frag_idx] = chunk
            self.nbytes += len(chunk)
        if len(self.chunks) == self.count:
            return b"".join(self.chunks[i] for i in range(self.count))
        return None


class Reassembler:
    """Bounded table of in-progress reassemblies (oldest evicted first)."""

    def __init__(self, max_entries: int = 1024, max_bytes: int = 16 << 20):
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self.table: dict[tuple, Reassembly] = {}

    def add(self, key: tuple, hdr: HsHeader, chunk: bytes, now: float) -> bytes | None:
        if hdr.frag_count == 1:
            return chunk
        entry = self.table.get(key)
        if entry is None:
            while self.table and (len(self.table) >= self.max_entries or
                                  self._bytes() + hdr.total_len > self.max_bytes):
                self.table.pop(next(iter(self.table)))
            entry = self.table[key] = Reassembly(hdr, now)
        msg = entry.add(hdr, chunk)
        if msg is not None:
            del self.table[key]
        return msg

    def _bytes(self) -> int:
        return sum(e.nbytes for e in self.table.values())

    def expire(self, now: float) -> None:
        for key in [k for k, e in self.table.items() if now - e.created > REASSEMBLY_TIMEOUT]:
            del self.table[key]


def random_index(taken) -> int:
    while True:
        idx = int.from_bytes(os.urandom(4), "big")
        if idx and idx not in taken:
            return idx


# --------------------------------------------------------------------- DoS

class CookieJar:
    """Stateless return-routability cookies with a rotating secret.

    cookie = HMAC-SHA256(secret, ip | port | initiator index | initiator nonce)[:16]
    Checked before any expensive work, so a spoofed-source flood costs the
    responder one HMAC per packet and earns the attacker a 40-byte reply.
    """

    ROTATE = 120

    def __init__(self):
        self.secrets = [os.urandom(32), os.urandom(32)]
        self.rotated = time.monotonic()

    def _maybe_rotate(self, now: float) -> None:
        if now - self.rotated > self.ROTATE:
            self.secrets = [os.urandom(32), self.secrets[0]]
            self.rotated = now

    @staticmethod
    def _mac(secret: bytes, ip: str, port: int, index: int, nonce: bytes) -> bytes:
        msg = ip.encode() + b"|" + struct.pack(">HI", port, index) + nonce
        return hmac.new(secret, msg, hashlib.sha256).digest()[:16]

    def make(self, ip: str, port: int, index: int, nonce: bytes, now: float) -> bytes:
        self._maybe_rotate(now)
        return self._mac(self.secrets[0], ip, port, index, nonce)

    def check(self, cookie: bytes, ip: str, port: int, index: int, nonce: bytes, now: float) -> bool:
        self._maybe_rotate(now)
        return len(cookie) == 16 and any(
            hmac.compare_digest(cookie, self._mac(s, ip, port, index, nonce)) for s in self.secrets)


class RateLimiter:
    """Per-source token bucket for handshake initiations."""

    def __init__(self, rate: float, burst: float, max_sources: int = 65536):
        self.rate, self.burst, self.max_sources = rate, burst, max_sources
        self.buckets: dict[str, list[float]] = {}

    def allow(self, key: str, now: float) -> bool:
        b = self.buckets.get(key)
        if b is None:
            if len(self.buckets) >= self.max_sources:
                self.prune(now)
                if len(self.buckets) >= self.max_sources:
                    return False
            b = self.buckets[key] = [self.burst, now]
        b[0] = min(self.burst, b[0] + (now - b[1]) * self.rate)
        b[1] = now
        if b[0] < 1:
            return False
        b[0] -= 1
        return True

    def prune(self, now: float) -> None:
        full = self.burst / self.rate
        for k in [k for k, b in self.buckets.items() if now - b[1] > full]:
            del self.buckets[k]
