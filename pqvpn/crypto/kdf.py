"""HKDF (RFC 5869) and the pqvpn key schedule.

The schedule mirrors TLS 1.3 (RFC 8446 s7.1), whose structure has extensive
formal analysis, with three layers:

          0 / PSK
             |
      HKDF-Extract = Early Secret
             |
      Derive-Secret(., "derived", "")
             v
 KEM_ss || ... || ECDH_ss -> HKDF-Extract = Handshake Secret
             |
             +--> Derive-Secret(., "i hs traffic", TH(M1..M2))
             +--> Derive-Secret(., "r hs traffic", TH(M1..M2))
             |
      Derive-Secret(., "derived", "")
             v
          0 -> HKDF-Extract = Master Secret
             |
             +--> Derive-Secret(., "i ap traffic", TH(M1..M4))
             +--> Derive-Secret(., "r ap traffic", TH(M1..M4))

The optional pre-shared key adds a third independent secret (defence in depth,
in the spirit of RFC 8784 / WireGuard's PSK): an adversary must break ML-KEM,
the classical ECDH *and* know the PSK.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

LABEL_PREFIX = b"pqvpn1 "


def hkdf_extract(hash_name: str, salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(hashlib.new(hash_name).digest_size)
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(hash_name: str, prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hash_name).digest()
        out += block
        counter += 1
    return out[:length]


def expand_label(hash_name: str, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full = LABEL_PREFIX + label
    info = struct.pack(">HB", length, len(full)) + full + bytes([len(context)]) + context
    return hkdf_expand(hash_name, secret, info, length)


class KeySchedule:
    def __init__(self, hash_name: str, key_len: int, psk: bytes | None = None):
        self.h = hash_name
        self.hlen = hashlib.new(hash_name).digest_size
        self.key_len = key_len
        zeros = bytes(self.hlen)
        early = hkdf_extract(self.h, zeros, psk or zeros)
        self._derived_early = self._derive(early, b"derived", self._empty_hash())
        self._hs: bytes | None = None
        self._master: bytes | None = None

    def _empty_hash(self) -> bytes:
        return hashlib.new(self.h).digest()

    def _derive(self, secret: bytes, label: bytes, th: bytes) -> bytes:
        return expand_label(self.h, secret, label, th, self.hlen)

    def key(self, traffic_secret: bytes) -> bytes:
        return expand_label(self.h, traffic_secret, b"key", b"", self.key_len)

    def finished_key(self, traffic_secret: bytes) -> bytes:
        return expand_label(self.h, traffic_secret, b"finished", b"", self.hlen)

    def finished_mac(self, traffic_secret: bytes, th: bytes) -> bytes:
        return hmac.new(self.finished_key(traffic_secret), th, self.h).digest()

    def handshake(self, shared_secret: bytes, th2: bytes) -> tuple[bytes, bytes]:
        """Return (initiator, responder) handshake traffic secrets."""
        hs = hkdf_extract(self.h, self._derived_early, shared_secret)
        self._master = hkdf_extract(self.h, self._derive(hs, b"derived", self._empty_hash()),
                                    bytes(self.hlen))
        return self._derive(hs, b"i hs traffic", th2), self._derive(hs, b"r hs traffic", th2)

    def traffic(self, th4: bytes) -> tuple[bytes, bytes]:
        """Return (initiator->responder, responder->initiator) data keys."""
        assert self._master is not None, "handshake() first"
        i2r = self._derive(self._master, b"i ap traffic", th4)
        r2i = self._derive(self._master, b"r ap traffic", th4)
        self._master = None  # one use only
        return self.key(i2r), self.key(r2i)
