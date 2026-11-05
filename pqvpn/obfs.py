"""Stealth mode: an outer obfuscation layer that hides what ShieldsVPN traffic is (ShieldsVPN obfs v1).

Why
    The inner protocol (PROTOCOL.md v1) is easy to fingerprint on the wire: the first byte is a fixed packet type
    (0x01 / 0x04), the data counter travels in clear, handshake datagrams are a fixed 1216 bytes, and it rides a
    fixed UDP port.  A censor's deep-packet-inspection box matches any of those and drops the flow.

What this does
    Every datagram is wrapped so the whole thing -- including the inner header -- becomes a short random nonce
    followed by authenticated ciphertext and a random amount of padding.  There is no fixed byte, no fixed length
    and no plaintext counter left to match, and a packet that does not authenticate under the obfuscation key is
    dropped with no reply, so the port does not answer a censor's probes.  Combined with running on UDP 443, the
    flow looks like meaningless UDP rather than a known VPN.

What it is NOT
    * Not extra confidentiality for your traffic: the inner protocol already encrypts and authenticates everything.
      This layer only changes how the packets *look*.
    * Not an authentication secret.  Anyone who can install the app can obtain the obfuscation key, so a determined
      censor can too.  The win is that ShieldsVPN is no longer caught by generic "block known-VPN / block unknown
      UDP" rules; a censor has to target ShieldsVPN specifically.
    * Not protection against the data-centre IP range being blocked wholesale, and not a defence against traffic
      timing/volume analysis.  See PROTOCOL.md section 8 for the honest threat model.

Crypto comes from OpenSSL (``ossl.AEAD``); there is no home-made cipher here.  The layer is symmetric and stateless
per packet, so it adds no handshake and works on every datagram the node sends or receives.
"""

from __future__ import annotations

import os
import struct

from .crypto import ossl
from .crypto.kdf import hkdf_expand, hkdf_extract

OBFS_VERSION = 1
CIPHER = "ChaCha20-Poly1305"   # constant-time in software, no AES-NI needed (the default data suite uses it too)
NONCE = 12
TAG = 16
LEN = 2                        # u16 inner length, inside the encrypted plaintext
MIN_WIRE = NONCE + LEN + TAG   # 30: smaller than this cannot be one of ours
MAX_INNER = 0xFFFF
# Pad only up to the point where an obfuscated datagram still fits the IPv6 minimum MTU (1280).  A plaintext
# handshake fragment is 1216 bytes, so this lets it pad a little and stay within 1280 on the wire; larger inner
# datagrams (data packets) are not padded (the data path already pads the inner IP packet).
PAD_CEILING = 1280 - MIN_WIRE  # 1250
DEFAULT_PAD_MAX = 64
_CONTEXT = b"pqvpn obfs v1"


def derive_key(secret: bytes) -> bytes:
    """A 32-byte obfuscation key from the configured secret, so the key on the wire is not the operator's raw file."""
    prk = hkdf_extract("sha256", _CONTEXT, secret)
    return hkdf_expand("sha256", prk, _CONTEXT + b" key", 32)


class Obfuscator:
    """Wraps and unwraps datagrams under one obfuscation key.  Used on the event-loop thread only (no locking)."""

    __slots__ = ("_seal", "_open", "pad_max")

    def __init__(self, secret: bytes, pad_max: int = DEFAULT_PAD_MAX):
        key = derive_key(secret)
        self._seal = ossl.AEAD(CIPHER, key, True)
        self._open = ossl.AEAD(CIPHER, key, False)
        self.pad_max = max(0, int(pad_max))

    def _pad_len(self, inner_len: int) -> int:
        cap = min(self.pad_max, max(0, PAD_CEILING - inner_len))
        if cap <= 0:
            return 0
        return int.from_bytes(os.urandom(2), "big") % (cap + 1)

    def wrap(self, datagram: bytes) -> bytes:
        """Obfuscate one outgoing datagram: nonce || AEAD(nonce, u16 len || datagram || random padding)."""
        n = len(datagram)
        if n > MAX_INNER:
            raise ValueError("datagram too large to obfuscate")
        nonce = os.urandom(NONCE)
        plaintext = struct.pack(">H", n) + bytes(datagram) + os.urandom(self._pad_len(n))
        return nonce + self._seal.seal(nonce, b"", plaintext)

    def unwrap(self, data: bytes) -> bytes | None:
        """Recover the inner datagram, or None if ``data`` is not a packet sealed with our key (dropped silently)."""
        if len(data) < MIN_WIRE:
            return None
        nonce = bytes(data[:NONCE])
        plaintext = self._open.open(nonce, b"", bytes(data[NONCE:]))
        if plaintext is None or len(plaintext) < LEN:
            return None
        n = (plaintext[0] << 8) | plaintext[1]
        if LEN + n > len(plaintext):
            return None
        return plaintext[LEN:LEN + n]
