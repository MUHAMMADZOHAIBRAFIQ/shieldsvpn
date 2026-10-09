"""Crypto-agility registry.

Nothing outside this module names a concrete algorithm.  The protocol carries
16-bit codepoints; adding or retiring an algorithm is a registry change plus a
policy (config) change, never a protocol change.

Key exchange follows the RFC 9370 / draft-ietf-tls-ecdhe-mlkem pattern: a suite
is an ordered list of independent key-exchange components whose shared secrets
are concatenated (PQ first) into the key schedule, with every public value bound
by the transcript hash.  The session stays secure while *any* component holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import ossl

# --------------------------------------------------------------------- KEX


class KexComponent:
    """One key-exchange component (a KEM, or ECDH modelled as a KEM)."""

    name: str
    share_len: int     # initiator -> responder
    response_len: int  # responder -> initiator

    def initiator_share(self) -> tuple[object, bytes]:
        raise NotImplementedError

    def responder_respond(self, share: bytes) -> tuple[bytes, bytes]:
        """Return (response, shared_secret)."""
        raise NotImplementedError

    def initiator_finish(self, state: object, response: bytes) -> bytes:
        raise NotImplementedError


class MLKEM(KexComponent):
    def __init__(self, name: str, ek_len: int, ct_len: int):
        self.name, self.share_len, self.response_len = name, ek_len, ct_len

    def initiator_share(self):
        dk = ossl.generate(self.name)
        return dk, ossl.raw_public(dk)

    def responder_respond(self, share):
        if len(share) != self.share_len:
            raise ValueError(f"{self.name}: bad encapsulation key length")
        ek = ossl.load_raw_public(self.name, share)  # FIPS 203 ek input check
        ct, ss = ossl.encapsulate(ek)
        return ct, ss

    def initiator_finish(self, dk, response):
        if len(response) != self.response_len:
            raise ValueError(f"{self.name}: bad ciphertext length")
        return ossl.decapsulate(dk, response)  # implicit rejection on bad ct


class ECDH(KexComponent):
    def __init__(self, name: str, pub_len: int, group: str | None = None):
        self.name, self.share_len, self.response_len = name, pub_len, pub_len
        self.group = group

    def _generate(self):
        if self.group:
            return ossl.generate("EC", self.group)
        return ossl.generate(self.name)

    def _public(self, key):
        return ossl.encoded_public(key) if self.group else ossl.raw_public(key)

    def _load(self, data: bytes):
        if len(data) != self.share_len:
            raise ValueError(f"{self.name}: bad public key length")
        if self.group:
            return ossl.load_ec_public(self.group, data)
        return ossl.load_raw_public(self.name, data)

    def _dh(self, own, peer_bytes):
        ss = ossl.derive(own, self._load(peer_bytes))
        if not any(ss):  # small-order / identity point
            raise ValueError(f"{self.name}: degenerate shared secret")
        return ss

    def initiator_share(self):
        key = self._generate()
        return key, self._public(key)

    def responder_respond(self, share):
        key = self._generate()
        return self._public(key), self._dh(key, share)

    def initiator_finish(self, key, response):
        return self._dh(key, response)


ML_KEM_768 = MLKEM("ML-KEM-768", 1184, 1088)
ML_KEM_1024 = MLKEM("ML-KEM-1024", 1568, 1568)
X25519 = ECDH("X25519", 32)
P384 = ECDH("P-384", 97, group="P-384")

# --------------------------------------------------------------------- suites


@dataclass(frozen=True)
class Suite:
    id: int
    name: str
    kex: tuple[KexComponent, ...]
    aead: str
    hash: str
    key_len: int
    # Per-key packet limits (draft-irtf-cfrg-aead-limits): AES-GCM's integrity
    # bound is far tighter than ChaCha20-Poly1305's, so it rekeys sooner.
    rekey_after_messages: int
    description: str = field(default="", compare=False)

    @property
    def hash_len(self) -> int:
        return {"sha256": 32, "sha384": 48, "sha512": 64}[self.hash]


SUITES: dict[int, Suite] = {s.id: s for s in (
    Suite(0x0001, "MLKEM768-X25519_CHACHA20POLY1305_SHA384", (ML_KEM_768, X25519),
          "ChaCha20-Poly1305", "sha384", 32, 1 << 60,
          "Default. Hybrid ML-KEM-768 + X25519 (NIST cat. 3), fast in software."),
    Suite(0x0002, "MLKEM768-X25519_AES256GCM_SHA384", (ML_KEM_768, X25519),
          "AES-256-GCM", "sha384", 32, 1 << 28,
          "Hybrid ML-KEM-768 + X25519 with AES-256-GCM (AES-NI hardware)."),
    Suite(0x0003, "MLKEM1024-P384_AES256GCM_SHA384", (ML_KEM_1024, P384),
          "AES-256-GCM", "sha384", 32, 1 << 28,
          "CNSA 2.0 transition profile: ML-KEM-1024 + ECDH P-384 (cat. 5)."),
    Suite(0x0004, "MLKEM1024_AES256GCM_SHA384", (ML_KEM_1024,),
          "AES-256-GCM", "sha384", 32, 1 << 28,
          "Pure post-quantum (CNSA 2.0 final). Not hybrid: opt-in only."),
)}

SUITES_BY_NAME = {s.name: s for s in SUITES.values()}
DEFAULT_SUITES = ("MLKEM768-X25519_CHACHA20POLY1305_SHA384",
                  "MLKEM768-X25519_AES256GCM_SHA384",
                  "MLKEM1024-P384_AES256GCM_SHA384")

# --------------------------------------------------------------------- signatures


@dataclass(frozen=True)
class SigAlg:
    id: int
    name: str
    pub_len: int
    sig_len: int
    family: str  # "ML-DSA" (FIPS 204) or "SLH-DSA" (FIPS 205)

    def generate(self) -> ossl.PKey:
        return ossl.generate(self.name)

    def public_bytes(self, key: ossl.PKey) -> bytes:
        return ossl.raw_public(key)

    def load_public(self, data: bytes) -> ossl.PKey:
        if len(data) != self.pub_len:
            raise ValueError(f"{self.name}: bad public key length")
        return ossl.load_raw_public(self.name, data)

    def sign(self, key: ossl.PKey, msg: bytes, context: bytes) -> bytes:
        return ossl.sign(key, msg, context)

    def verify(self, pub: ossl.PKey, msg: bytes, sig: bytes, context: bytes) -> bool:
        return len(sig) == self.sig_len and ossl.verify(pub, msg, sig, context)


SIG_ALGS: dict[int, SigAlg] = {a.id: a for a in (
    SigAlg(0x0101, "ML-DSA-44", 1312, 2420, "ML-DSA"),
    SigAlg(0x0102, "ML-DSA-65", 1952, 3309, "ML-DSA"),
    SigAlg(0x0103, "ML-DSA-87", 2592, 4627, "ML-DSA"),
    SigAlg(0x0201, "SLH-DSA-SHA2-128s", 32, 7856, "SLH-DSA"),
    SigAlg(0x0202, "SLH-DSA-SHA2-128f", 32, 17088, "SLH-DSA"),
    SigAlg(0x0203, "SLH-DSA-SHA2-192s", 48, 16224, "SLH-DSA"),
    SigAlg(0x0204, "SLH-DSA-SHA2-192f", 48, 35664, "SLH-DSA"),
    SigAlg(0x0205, "SLH-DSA-SHA2-256s", 64, 29792, "SLH-DSA"),
    SigAlg(0x0206, "SLH-DSA-SHA2-256f", 64, 49856, "SLH-DSA"),
    SigAlg(0x0211, "SLH-DSA-SHAKE-128s", 32, 7856, "SLH-DSA"),
    SigAlg(0x0213, "SLH-DSA-SHAKE-192s", 48, 16224, "SLH-DSA"),
    SigAlg(0x0215, "SLH-DSA-SHAKE-256s", 64, 29792, "SLH-DSA"),
)}

SIG_ALGS_BY_NAME = {a.name: a for a in SIG_ALGS.values()}
DEFAULT_PEER_SIG_ALGS = ("ML-DSA-65", "ML-DSA-87")
DEFAULT_CA_SIG_ALGS = ("SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-192s",
                       "SLH-DSA-SHAKE-256s", "ML-DSA-87")


def suite_by_name(name: str) -> Suite:
    try:
        return SUITES_BY_NAME[name]
    except KeyError:
        raise ValueError(f"unknown suite {name!r}; known: {', '.join(SUITES_BY_NAME)}") from None


def sig_alg_by_name(name: str) -> SigAlg:
    try:
        return SIG_ALGS_BY_NAME[name]
    except KeyError:
        raise ValueError(f"unknown signature algorithm {name!r}; known: {', '.join(SIG_ALGS_BY_NAME)}") from None


def describe_suite(name: str) -> str:
    """Human-readable suite label, e.g. 'ML-KEM-768 + X25519 · ChaCha20-Poly1305'."""
    s = SUITES_BY_NAME.get(name)
    if s is None:
        return name
    return " + ".join(c.name for c in s.kex) + " · " + s.aead
