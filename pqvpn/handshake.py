"""Handshake state machines -- pure protocol logic, no I/O.

    Initiator (client)                                Responder (server)
    ------------------                                ------------------
    INIT      nonce_i, offered suites,       ---->
              key shares {ML-KEM ek, ECDH pub},
              [cookie]
                                             <----    [COOKIE c]   (under load)
                                             <----    [RETRY s]    (other suite)
                                             <----    RESPONSE  nonce_r, suite,
                                                                {ML-KEM ct, ECDH pub}
          ss = ML-KEM ss || ECDH ss  ->  handshake secrets (kdf.KeySchedule)
    AUTH_I  {cert_I, Sig_I(TH), Fin_I}       ---->
                                             <----    AUTH_R  {cert_R, Sig_R(TH), config, Fin_R}
          traffic keys = KDF(master, TH(INIT..AUTH_R))

{..} = AEAD under handshake keys, per fragment.

Properties
  * Hybrid confidentiality: secure if ML-KEM *or* the ECDH component holds.
  * Forward secrecy (incl. against quantum adversaries): ML-KEM and ECDH keys
    are ephemeral, generated per handshake and discarded.
  * Mutual authentication with post-quantum signatures over the full
    transcript (SIGMA-style "sign-and-MAC"), which also gives downgrade
    protection: the offered suite list is in the signed transcript.
  * Identity protection: both certificates travel encrypted.  As in IKEv2 the
    initiator reveals its identity first (to whoever completed the KEM).
  * No amplification: the large authenticated messages flow only after the
    initiator has proven reachability by completing INIT/RESPONSE, and
    RESPONSE is no larger than INIT.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass
from typing import Callable

from .crypto import ossl
from .crypto.kdf import KeySchedule
from .crypto.suites import SUITES, Suite
from .pki import ROLE_CLIENT, ROLE_SERVER, Certificate, CertError, Identity, TrustStore
from .protocol import (MT_AUTH_I, MT_AUTH_R, MT_COOKIE, MT_INIT, MT_RESPONSE, MT_RETRY, VERSION,
                       CookieJar, HsHeader, Reassembly, fragment, fragment_nonce, random_index)
from .wire import DecodeError, Reader, Writer

CTX_AUTH_I = b"pqvpn1 initiator CertificateVerify"
CTX_AUTH_R = b"pqvpn1 responder CertificateVerify"
MAX_RETRIES = 4


class HandshakeError(Exception):
    pass


@dataclass(frozen=True)
class Policy:
    suites: tuple[Suite, ...]      # preference order
    psk: bytes | None = None


@dataclass
class Result:
    suite: Suite
    local_index: int
    remote_index: int
    send_key: bytes
    recv_key: bytes
    peer_cert: Certificate
    initiator: bool
    config: dict | None = None


class Transcript:
    def __init__(self):
        self.entries: list[bytes] = []

    def add(self, mt: int, sender: int, receiver: int, body: bytes) -> None:
        self.entries.append(struct.pack(">BIII", mt, sender, receiver, len(body)) + body)

    def hash(self, name: str, *extra: bytes) -> bytes:
        h = hashlib.new(name)
        for e in self.entries:
            h.update(e)
        for e in extra:
            h.update(e)
        return h.digest()


def _vec32(b: bytes) -> bytes:
    return Writer().vec32(b).bytes()


def _vec16(b: bytes) -> bytes:
    return Writer().vec16(b).bytes()


# ------------------------------------------------------------------ messages

@dataclass
class InitMsg:
    version: int
    nonce: bytes
    offered: tuple[int, ...]
    share_suite: int
    shares: tuple[bytes, ...]
    cookie: bytes


def encode_init(m: InitMsg) -> bytes:
    w = Writer().u8(m.version).raw(m.nonce).u8(len(m.offered))
    for s in m.offered:
        w.u16(s)
    w.u16(m.share_suite).u8(len(m.shares))
    for s in m.shares:
        w.vec16(s)
    return w.vec8(m.cookie).bytes()


def decode_init(body: bytes) -> InitMsg:
    r = Reader(body)
    version, nonce = r.u8(), r.take(32)
    offered = tuple(r.u16() for _ in range(r.u8()))
    share_suite = r.u16()
    shares = tuple(r.vec16() for _ in range(r.u8()))
    cookie = r.vec8()
    r.done()
    return InitMsg(version, nonce, offered, share_suite, shares, cookie)


def encode_response(nonce: bytes, suite_id: int, responses: list[bytes]) -> bytes:
    w = Writer().raw(nonce).u16(suite_id).u8(len(responses))
    for x in responses:
        w.vec16(x)
    return w.bytes()


def decode_response(body: bytes) -> tuple[bytes, int, tuple[bytes, ...]]:
    r = Reader(body)
    nonce, suite_id = r.take(32), r.u16()
    responses = tuple(r.vec16() for _ in range(r.u8()))
    r.done()
    return nonce, suite_id, responses


# ------------------------------------------------------------------ initiator

class Initiator:
    def __init__(self, identity: Identity, trust: TrustStore, policy: Policy, server_name: str,
                 taken_indices=()):
        self.identity, self.trust, self.policy, self.server_name = identity, trust, policy, server_name
        self.index = random_index(taken_indices)
        self.suite = policy.suites[0]
        self.nonce = os.urandom(32)
        self.cookie = b""
        self.retries = 0
        self.state = "init"
        self.r_index = 0
        self._new_shares()
        self.flight = self._build_init()

    def _new_shares(self) -> None:
        pairs = [c.initiator_share() for c in self.suite.kex]
        self._kex_state = [p[0] for p in pairs]
        self._shares = tuple(p[1] for p in pairs)

    def _build_init(self) -> list[bytes]:
        self.m1 = encode_init(InitMsg(VERSION, self.nonce, tuple(s.id for s in self.policy.suites),
                                      self.suite.id, self._shares, self.cookie))
        return fragment(MT_INIT, self.index, 0, self.m1)

    def on_retry(self, hdr: HsHeader, body: bytes) -> list[bytes] | None:
        if self.state != "init" or hdr.receiver != self.index or self.retries >= MAX_RETRIES:
            return None
        r = Reader(body)
        suite = SUITES.get(r.u16())
        r.done()
        if suite is None or suite not in self.policy.suites or suite == self.suite:
            return None
        self.retries += 1
        self.suite = suite
        self._new_shares()  # nonce kept so an earlier cookie stays valid
        self.flight = self._build_init()
        return self.flight

    def on_cookie(self, hdr: HsHeader, body: bytes) -> list[bytes] | None:
        if self.state != "init" or hdr.receiver != self.index or self.retries >= MAX_RETRIES:
            return None
        r = Reader(body)
        cookie = r.vec8()
        r.done()
        if len(cookie) != 16:
            return None
        self.retries += 1
        self.cookie = cookie
        self.flight = self._build_init()
        return self.flight

    def on_response(self, hdr: HsHeader, body: bytes) -> list[bytes] | None:
        if self.state != "init" or hdr.receiver != self.index or hdr.sender == 0:
            return None
        _nonce_r, suite_id, responses = decode_response(body)
        suite = self.suite
        if suite_id != suite.id or len(responses) != len(suite.kex):
            raise HandshakeError("RESPONSE does not match offered key shares")
        try:
            ss = b"".join(c.initiator_finish(st, resp)
                          for c, st, resp in zip(suite.kex, self._kex_state, responses))
        except (ValueError, ossl.OpenSSLError) as exc:
            raise HandshakeError(f"key exchange failed: {exc}") from None
        self._kex_state = []  # drop ephemeral private keys
        self.r_index = hdr.sender
        h = suite.hash
        tr = self.tr = Transcript()
        tr.add(MT_INIT, self.index, 0, self.m1)
        tr.add(MT_RESPONSE, self.r_index, self.index, body)
        self.ks = KeySchedule(h, suite.key_len, self.policy.psk)
        hs_i, self.hs_r = self.ks.handshake(ss, tr.hash(h))

        cert_part = _vec32(self.identity.cert_bytes)
        sig_part = _vec16(self.identity.sign(tr.hash(h, cert_part), CTX_AUTH_I))
        fin = self.ks.finished_mac(hs_i, tr.hash(h, cert_part, sig_part))
        m3 = cert_part + sig_part + fin
        tr.add(MT_AUTH_I, self.index, self.r_index, m3)

        sealer = ossl.AEAD(suite.aead, self.ks.key(hs_i), True)
        self._opener = ossl.AEAD(suite.aead, self.ks.key(self.hs_r), False)
        self._reasm: Reassembly | None = None
        self.state = "auth"
        self.flight = fragment(MT_AUTH_I, self.index, self.r_index, m3, sealer.seal)
        return self.flight

    def on_auth_fragment(self, hdr: HsHeader, payload: bytes, now: float) -> Result | None:
        if (self.state != "auth" or hdr.msg_type != MT_AUTH_R or hdr.receiver != self.index
                or hdr.sender != self.r_index):
            return None
        chunk = self._opener.open(fragment_nonce(MT_AUTH_R, hdr.frag_idx), hdr.raw, payload)
        if chunk is None:
            return None  # forged / corrupted fragment: ignore, keep waiting
        if self._reasm is None:
            self._reasm = Reassembly(hdr, now)
        body = self._reasm.add(hdr, chunk)
        if body is None:
            return None
        self._reasm = None
        return self._finish(body)

    def _finish(self, body: bytes) -> Result:
        suite, h, tr = self.suite, self.suite.hash, self.tr
        try:
            r = Reader(body)
            cert_b, sig, cfg_b, fin = r.vec32(), r.vec16(), r.vec16(), r.take(suite.hash_len)
            r.done()
        except DecodeError as exc:
            raise HandshakeError(f"malformed AUTH_R: {exc}") from None
        cert_part, sig_part, cfg_part = _vec32(cert_b), _vec16(sig), _vec16(cfg_b)
        if not hmac.compare_digest(fin, self.ks.finished_mac(self.hs_r, tr.hash(h, cert_part, sig_part, cfg_part))):
            raise HandshakeError("responder Finished MAC invalid")
        try:
            cert = Certificate.decode(cert_b)
            self.trust.verify(cert, ROLE_SERVER, subject=self.server_name)
        except CertError as exc:
            raise HandshakeError(f"server certificate rejected: {exc}") from None
        pub = cert.key_alg.load_public(cert.public_key)
        if not cert.key_alg.verify(pub, tr.hash(h, cert_part), sig, CTX_AUTH_R):
            raise HandshakeError("server signature invalid")
        try:
            config = json.loads(cfg_b.decode("utf-8")) if cfg_b else {}
        except ValueError:
            raise HandshakeError("server config is not valid JSON") from None
        tr.add(MT_AUTH_R, self.r_index, self.index, body)
        i2r, r2i = self.ks.traffic(tr.hash(h))
        self.state = "done"
        return Result(suite, self.index, self.r_index, i2r, r2i, cert, True, config)


# ------------------------------------------------------------------ responder

class ResponderHandshake:
    """Responder state from RESPONSE until the session is confirmed."""

    def __init__(self, responder: "Responder", suite: Suite, ks: KeySchedule, hs_i: bytes, hs_r: bytes,
                 tr: Transcript, r_index: int, i_index: int, addr, now: float, m1_digest: bytes,
                 m2_flight: list[bytes]):
        self.responder, self.suite, self.ks, self.tr = responder, suite, ks, tr
        self.hs_i, self.hs_r = hs_i, hs_r
        self.r_index, self.i_index, self.addr = r_index, i_index, addr
        self.created = now
        self.m1_digest = m1_digest
        self.m2_flight = m2_flight
        self.m3_digest: bytes | None = None
        self.m4_flight: list[bytes] | None = None
        self._opener = ossl.AEAD(suite.aead, ks.key(hs_i), False)
        self._reasm: Reassembly | None = None

    def on_auth_fragment(self, hdr: HsHeader, payload: bytes, now: float) -> tuple[list[bytes], Result | None]:
        if hdr.msg_type != MT_AUTH_I or hdr.sender != self.i_index:
            return [], None
        chunk = self._opener.open(fragment_nonce(MT_AUTH_I, hdr.frag_idx), hdr.raw, payload)
        if chunk is None:
            return [], None
        if self._reasm is None:
            self._reasm = Reassembly(hdr, now)
        body = self._reasm.add(hdr, chunk)
        if body is None:
            return [], None
        self._reasm = None
        digest = hashlib.sha256(body).digest()
        if self.m4_flight is not None:  # retransmitted AUTH_I: our AUTH_R was lost
            return (self.m4_flight if digest == self.m3_digest else []), None
        result = self._process(body)
        self.m3_digest = digest
        return self.m4_flight, result

    def _process(self, body: bytes) -> Result:
        suite, h, tr, rsp = self.suite, self.suite.hash, self.tr, self.responder
        try:
            r = Reader(body)
            cert_b, sig, fin = r.vec32(), r.vec16(), r.take(suite.hash_len)
            r.done()
        except DecodeError as exc:
            raise HandshakeError(f"malformed AUTH_I: {exc}") from None
        cert_part, sig_part = _vec32(cert_b), _vec16(sig)
        if not hmac.compare_digest(fin, self.ks.finished_mac(self.hs_i, tr.hash(h, cert_part, sig_part))):
            raise HandshakeError("initiator Finished MAC invalid")
        try:
            cert = Certificate.decode(cert_b)
            rsp.trust.verify(cert, ROLE_CLIENT)
        except CertError as exc:
            raise HandshakeError(f"client certificate rejected: {exc}") from None
        pub = cert.key_alg.load_public(cert.public_key)
        if not cert.key_alg.verify(pub, tr.hash(h, cert_part), sig, CTX_AUTH_I):
            raise HandshakeError(f"client signature invalid ({cert.subject})")
        tr.add(MT_AUTH_I, self.i_index, self.r_index, body)

        config = rsp.config_for(cert)  # may raise HandshakeError (policy)
        cfg_part = _vec16(json.dumps(config, separators=(",", ":")).encode())
        own_part = _vec32(rsp.identity.cert_bytes)
        own_sig = _vec16(rsp.identity.sign(tr.hash(h, own_part), CTX_AUTH_R))
        fin_r = self.ks.finished_mac(self.hs_r, tr.hash(h, own_part, own_sig, cfg_part))
        m4 = own_part + own_sig + cfg_part + fin_r
        tr.add(MT_AUTH_R, self.r_index, self.i_index, m4)
        i2r, r2i = self.ks.traffic(tr.hash(h))
        sealer = ossl.AEAD(suite.aead, self.ks.key(self.hs_r), True)
        self.m4_flight = fragment(MT_AUTH_R, self.r_index, self.i_index, m4, sealer.seal)
        return Result(suite, self.r_index, self.i_index, r2i, i2r, cert, False, config)


class Responder:
    def __init__(self, identity: Identity, trust: TrustStore, policy: Policy,
                 config_for: Callable[[Certificate], dict]):
        self.identity, self.trust, self.policy, self.config_for = identity, trust, policy, config_for
        self.cookies = CookieJar()

    def on_init(self, hdr: HsHeader, body: bytes, addr: tuple, now: float, *, require_cookie: bool,
                taken_indices) -> tuple[list[bytes], ResponderHandshake | None]:
        """Process INIT.  Returns datagrams to send and, if accepted, new state."""
        if hdr.receiver != 0 or hdr.sender == 0:
            raise HandshakeError("bad INIT indices")
        msg = decode_init(body)
        if msg.version != VERSION:
            raise HandshakeError(f"unsupported version {msg.version}")
        ip, port = addr[0], addr[1]
        if require_cookie and not self.cookies.check(msg.cookie, ip, port, hdr.sender, msg.nonce, now):
            cookie = self.cookies.make(ip, port, hdr.sender, msg.nonce, now)
            return fragment(MT_COOKIE, 0, hdr.sender, Writer().vec8(cookie).bytes()), None

        suite = next((s for s in self.policy.suites if s.id in msg.offered), None)
        if suite is None:
            raise HandshakeError("no mutually acceptable cipher suite")
        if suite.id != msg.share_suite:
            return fragment(MT_RETRY, 0, hdr.sender, struct.pack(">H", suite.id)), None
        if len(msg.shares) != len(suite.kex):
            raise HandshakeError("wrong number of key shares")
        try:
            pairs = [c.responder_respond(s) for c, s in zip(suite.kex, msg.shares)]
        except (ValueError, ossl.OpenSSLError) as exc:
            raise HandshakeError(f"invalid key share: {exc}") from None

        r_index = random_index(taken_indices)
        m2 = encode_response(os.urandom(32), suite.id, [p[0] for p in pairs])
        h = suite.hash
        tr = Transcript()
        tr.add(MT_INIT, hdr.sender, 0, body)
        tr.add(MT_RESPONSE, r_index, hdr.sender, m2)
        ks = KeySchedule(h, suite.key_len, self.policy.psk)
        hs_i, hs_r = ks.handshake(b"".join(p[1] for p in pairs), tr.hash(h))
        flight = fragment(MT_RESPONSE, r_index, hdr.sender, m2)
        state = ResponderHandshake(self, suite, ks, hs_i, hs_r, tr, r_index, hdr.sender, addr, now,
                                   hashlib.sha256(body).digest(), flight)
        return flight, state
