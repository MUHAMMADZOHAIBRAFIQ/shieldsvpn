"""Post-quantum PKI: SLH-DSA root CA -> ML-DSA device certificates.

Design notes
  * The root CA should use SLH-DSA (FIPS 205).  Its security rests only on the
    hash function, which is the most conservative assumption available for a
    trust anchor that lives for a decade and signs rarely (slow signing is
    irrelevant; verification is ~0.5 ms and results are cached).
  * Device (server / client) keys use ML-DSA (FIPS 204): small, fast signatures
    for the per-handshake CertificateVerify.
  * Certificates bind subject, role, validity and the tunnel addresses the
    holder may use, so the CA is the single source of truth for addressing and
    the server needs no per-client configuration.
  * Several CA certificates may be trusted at once, which is how a CA algorithm
    migration (crypto agility) is rolled out without a flag day.

Encoding (all integers big-endian), PEM-armoured as "PQVPN CERTIFICATE":
    magic "PQV1" | u8 version=1 | u8 role | serial[16] | vec8 subject(UTF-8)
    | u64 not_before | u64 not_after | u16 key_alg | vec16 public_key
    | u8 n_addrs { vec8 cidr(ASCII) } | issuer_key_id[32]
    --- end of TBS ---
    | u16 sig_alg | vec32 signature
Signature = Sign(issuer_key, TBS, ctx="pqvpn1 certificate").
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import time
from dataclasses import dataclass, replace

from .crypto import ossl
from .crypto.suites import SIG_ALGS, SigAlg
from .wire import DecodeError, Reader, Writer

ROLE_CA, ROLE_SERVER, ROLE_CLIENT = 1, 2, 3
ROLE_NAMES = {ROLE_CA: "ca", ROLE_SERVER: "server", ROLE_CLIENT: "client"}
ROLE_BY_NAME = {v: k for k, v in ROLE_NAMES.items()}

MAGIC = b"PQV1"
CERT_CONTEXT = b"pqvpn1 certificate"
PEM_LABEL = "PQVPN CERTIFICATE"
CLOCK_SKEW = 300
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:+\-]{0,63}$")


class CertError(Exception):
    pass


def key_id(alg: SigAlg, public_key: bytes) -> bytes:
    return hashlib.sha256(alg.id.to_bytes(2, "big") + public_key).digest()


def _norm_cidr(text: str) -> str:
    return str(ipaddress.ip_interface(text.strip()))


@dataclass(frozen=True)
class Certificate:
    role: int
    serial: bytes
    subject: str
    not_before: int
    not_after: int
    key_alg: SigAlg
    public_key: bytes
    addresses: tuple[str, ...]
    issuer_key_id: bytes
    sig_alg: SigAlg
    signature: bytes

    # -------------------------------------------------------------- encoding
    def tbs(self) -> bytes:
        w = Writer().raw(MAGIC).u8(1).u8(self.role).raw(self.serial)
        w.vec8(self.subject.encode()).u64(self.not_before).u64(self.not_after)
        w.u16(self.key_alg.id).vec16(self.public_key).u8(len(self.addresses))
        for a in self.addresses:
            w.vec8(a.encode("ascii"))
        return w.raw(self.issuer_key_id).bytes()

    def encode(self) -> bytes:
        return Writer().raw(self.tbs()).u16(self.sig_alg.id).vec32(self.signature).bytes()

    @classmethod
    def decode(cls, data: bytes) -> "Certificate":
        try:
            r = Reader(data)
            if r.take(4) != MAGIC or r.u8() != 1:
                raise CertError("not a pqvpn v1 certificate")
            role = r.u8()
            if role not in ROLE_NAMES:
                raise CertError("unknown role")
            serial = r.take(16)
            subject = r.vec8().decode("utf-8")
            not_before, not_after = r.u64(), r.u64()
            key_alg = _sig_alg(r.u16())
            public_key = r.vec16()
            addresses = tuple(_norm_cidr(r.vec8().decode("ascii")) for _ in range(r.u8()))
            issuer = r.take(32)
            sig_alg = _sig_alg(r.u16())
            signature = r.vec32()
            r.done()
        except (DecodeError, UnicodeDecodeError, ValueError) as exc:
            raise CertError(f"malformed certificate: {exc}") from None
        if len(public_key) != key_alg.pub_len:
            raise CertError("public key length does not match algorithm")
        cert = cls(role, serial, subject, not_before, not_after, key_alg, public_key,
                   addresses, issuer, sig_alg, signature)
        if cert.encode() != bytes(data):
            raise CertError("non-canonical certificate encoding")
        return cert

    def to_pem(self) -> str:
        b64 = base64.b64encode(self.encode()).decode()
        body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
        return f"-----BEGIN {PEM_LABEL}-----\n{body}\n-----END {PEM_LABEL}-----\n"

    @classmethod
    def from_pem(cls, text: str) -> "Certificate":
        m = re.search(rf"-----BEGIN {PEM_LABEL}-----(.*?)-----END {PEM_LABEL}-----", text, re.S)
        if not m:
            raise CertError("no PQVPN CERTIFICATE block found")
        return cls.decode(base64.b64decode("".join(m.group(1).split()), validate=True))

    @classmethod
    def load(cls, path: str) -> "Certificate":
        with open(path, encoding="ascii") as f:
            return cls.from_pem(f.read())

    # -------------------------------------------------------------- helpers
    @property
    def key_id(self) -> bytes:
        return key_id(self.key_alg, self.public_key)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.encode()).hexdigest()

    @property
    def serial_hex(self) -> str:
        return self.serial.hex()

    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_interface(a).network for a in self.addresses]

    def describe(self) -> str:
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))  # noqa: E731
        return "\n".join([
            f"Subject:       {self.subject}",
            f"Role:          {ROLE_NAMES[self.role]}",
            f"Serial:        {self.serial_hex}",
            f"Valid:         {fmt(self.not_before)}  ->  {fmt(self.not_after)}",
            f"Key:           {self.key_alg.name} ({len(self.public_key)} bytes)",
            f"Key ID:        {self.key_id.hex()}",
            f"Addresses:     {', '.join(self.addresses) or '-'}",
            f"Issuer key ID: {self.issuer_key_id.hex()}",
            f"Signature:     {self.sig_alg.name} ({len(self.signature)} bytes)",
            f"Fingerprint:   SHA256:{self.fingerprint}",
        ])


def _sig_alg(code: int) -> SigAlg:
    try:
        return SIG_ALGS[code]
    except KeyError:
        raise CertError(f"unknown signature algorithm 0x{code:04x}") from None


def issue(*, role: int, subject: str, key_alg: SigAlg, public_key: bytes, addresses: list[str],
          days: float, issuer_key: ossl.PKey, issuer_alg: SigAlg, issuer_public: bytes,
          not_before: int | None = None) -> Certificate:
    if not _SUBJECT_RE.match(subject):
        raise CertError("subject must be 1-64 chars of [A-Za-z0-9 ._@:+-]")
    if len(addresses) > 32:
        raise CertError("too many addresses")
    addrs = tuple(_norm_cidr(a) for a in addresses)
    start = int(time.time()) - 60 if not_before is None else not_before
    unsigned = Certificate(role, os.urandom(16), subject, start, start + int(days * 86400), key_alg,
                           public_key, addrs, key_id(issuer_alg, issuer_public), issuer_alg, b"")
    return replace(unsigned, signature=issuer_alg.sign(issuer_key, unsigned.tbs(), CERT_CONTEXT))


def self_sign_ca(subject: str, key: ossl.PKey, alg: SigAlg, days: float) -> Certificate:
    pub = alg.public_bytes(key)
    return issue(role=ROLE_CA, subject=subject, key_alg=alg, public_key=pub, addresses=[],
                 days=days, issuer_key=key, issuer_alg=alg, issuer_public=pub)


# ------------------------------------------------------------------ key files

def write_private_key(path: str, key: ossl.PKey, passphrase: bytes | None = None) -> None:
    data = ossl.private_to_pem(key, passphrase)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def read_private_key(path: str, passphrase: bytes | None = None) -> ossl.PKey:
    with open(path, "rb") as f:
        return ossl.private_from_pem(f.read(), passphrase)


def write_file(path: str, text: str) -> None:
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write(text)


# ------------------------------------------------------------------ identity / trust

class Identity:
    """A certificate together with its private key (checked to match)."""

    def __init__(self, cert: Certificate, key: ossl.PKey):
        if not key.is_a(cert.key_alg.name) or cert.key_alg.public_bytes(key) != cert.public_key:
            raise CertError("private key does not match certificate")
        self.cert, self.key = cert, key
        self.cert_bytes = cert.encode()

    @classmethod
    def load(cls, cert_path: str, key_path: str, passphrase: bytes | None = None) -> "Identity":
        return cls(Certificate.load(cert_path), read_private_key(key_path, passphrase))

    def sign(self, msg: bytes, context: bytes) -> bytes:
        return self.cert.key_alg.sign(self.key, msg, context)


class TrustStore:
    def __init__(self, ca_certs: list[Certificate], *, peer_algs: tuple[str, ...],
                 ca_algs: tuple[str, ...], revoked: set[str] | None = None):
        self.peer_algs = set(peer_algs)
        self.ca_algs = set(ca_algs)
        self.revoked = {s.lower() for s in (revoked or set())}
        self.cas: dict[bytes, Certificate] = {}
        self._verified: dict[bytes, bool] = {}
        for ca in ca_certs:
            if ca.role != ROLE_CA:
                raise CertError(f"{ca.subject}: trust anchor is not a CA certificate")
            if ca.issuer_key_id != ca.key_id:
                raise CertError(f"{ca.subject}: trust anchor is not self-signed")
            pub = ca.key_alg.load_public(ca.public_key)
            if not ca.key_alg.verify(pub, ca.tbs(), ca.signature, CERT_CONTEXT):
                raise CertError(f"{ca.subject}: CA self-signature invalid")
            self.cas[ca.key_id] = ca

    @classmethod
    def load(cls, paths: list[str], **kw) -> "TrustStore":
        return cls([Certificate.load(p) for p in paths], **kw)

    def verify(self, cert: Certificate, role: int, *, subject: str | None = None,
               now: float | None = None) -> None:
        """Raise CertError unless ``cert`` is acceptable for ``role`` right now."""
        now = time.time() if now is None else now
        if cert.role != role:
            raise CertError(f"certificate role is {ROLE_NAMES[cert.role]}, expected {ROLE_NAMES[role]}")
        if subject is not None and cert.subject != subject:
            raise CertError(f"certificate subject {cert.subject!r} != expected {subject!r}")
        if cert.key_alg.name not in self.peer_algs:
            raise CertError(f"peer key algorithm {cert.key_alg.name} not allowed by policy")
        if not cert.not_before - CLOCK_SKEW <= now <= cert.not_after + CLOCK_SKEW:
            raise CertError("certificate expired or not yet valid")
        if cert.serial_hex in self.revoked:
            raise CertError(f"certificate serial {cert.serial_hex} is revoked")
        ca = self.cas.get(cert.issuer_key_id)
        if ca is None:
            raise CertError("certificate not issued by a trusted CA")
        if ca.key_alg.name not in self.ca_algs or cert.sig_alg != ca.key_alg:
            raise CertError(f"CA algorithm {ca.key_alg.name} not allowed by policy")
        if not ca.not_before - CLOCK_SKEW <= now <= ca.not_after + CLOCK_SKEW:
            raise CertError("issuing CA certificate expired")
        if role == ROLE_CLIENT:
            nets = cert.networks()
            if not nets or nets[0].num_addresses != 1:
                raise CertError("client certificate's first address must be a single host (/32 or /128)")
        digest = hashlib.sha256(cert.encode()).digest()
        if digest not in self._verified:
            pub = ca.key_alg.load_public(ca.public_key)
            if not ca.key_alg.verify(pub, cert.tbs(), cert.signature, CERT_CONTEXT):
                raise CertError("certificate signature invalid")
            if len(self._verified) > 4096:
                self._verified.clear()
            self._verified[digest] = True
