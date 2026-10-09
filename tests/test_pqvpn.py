"""pqvpn test suite:  python -m unittest discover -s tests -v"""

from __future__ import annotations

import asyncio
import base64
import os
import random
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import pki  # noqa: E402
from pqvpn.crypto import kdf, ossl  # noqa: E402
from pqvpn.crypto.suites import SUITES_BY_NAME, X25519  # noqa: E402
from pqvpn.handshake import HandshakeError, Initiator, Policy, Responder, decode_init, encode_init  # noqa: E402
from pqvpn.protocol import (CHUNK, MT_AUTH_I, MT_INIT, PT_DATA, CookieJar, Reassembler,  # noqa: E402
                            fragment, parse_hs)
from pqvpn.runner import TestPKI, crypto_cfg, icmp_echo, loopback_pair, server_cfg  # noqa: E402
from pqvpn.session import ReplayWindow, RouteTable, pad, unpad  # noqa: E402
from pqvpn.wire import DecodeError  # noqa: E402

TP: TestPKI | None = None


def setUpModule():
    global TP
    TP = TestPKI(ca_alg="SLH-DSA-SHA2-128s")


def tp() -> TestPKI:
    assert TP is not None
    return TP


# ====================================================================== primitives

class TestPrimitives(unittest.TestCase):
    def test_hkdf_rfc5869_case1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = kdf.hkdf_extract("sha256", salt, ikm)
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = kdf.hkdf_expand("sha256", prk, info, 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                    "34007208d5b887185865")

    def test_every_suite_kex_agrees(self):
        for suite in SUITES_BY_NAME.values():
            for comp in suite.kex:
                st, share = comp.initiator_share()
                self.assertEqual(len(share), comp.share_len, comp.name)
                resp, ss_r = comp.responder_respond(share)
                self.assertEqual(len(resp), comp.response_len, comp.name)
                self.assertEqual(comp.initiator_finish(st, resp), ss_r, comp.name)

    def test_mlkem_implicit_rejection(self):
        comp = SUITES_BY_NAME["MLKEM768-X25519_CHACHA20POLY1305_SHA384"].kex[0]
        st, share = comp.initiator_share()
        ct, ss = comp.responder_respond(share)
        bad = bytes([ct[0] ^ 1]) + ct[1:]
        self.assertNotEqual(comp.initiator_finish(st, bad), ss)  # FIPS 203: pseudo-random, no error oracle

    def test_kex_rejects_bad_lengths_and_small_order(self):
        comp = SUITES_BY_NAME["MLKEM768-X25519_CHACHA20POLY1305_SHA384"].kex[0]
        with self.assertRaises(ValueError):
            comp.responder_respond(b"\0" * 10)
        with self.assertRaises((ValueError, ossl.OpenSSLError)):
            X25519.responder_respond(bytes(32))  # all-zero = small-order point

    def test_signature_context_separation(self):
        alg = tp().peer_alg
        key = alg.generate()
        pub = alg.load_public(alg.public_bytes(key))
        sig = alg.sign(key, b"msg", b"ctx-a")
        self.assertTrue(alg.verify(pub, b"msg", sig, b"ctx-a"))
        self.assertFalse(alg.verify(pub, b"msg", sig, b"ctx-b"))
        self.assertFalse(alg.verify(pub, b"msG", sig, b"ctx-a"))

    def test_aead_tamper(self):
        for name in ("ChaCha20-Poly1305", "AES-256-GCM"):
            k = os.urandom(32)
            e, d = ossl.AEAD(name, k, True), ossl.AEAD(name, k, False)
            n = os.urandom(12)
            ct = e.seal(n, b"hdr", b"payload")
            self.assertEqual(d.open(n, b"hdr", ct), b"payload")
            for i in range(len(ct)):
                bad = bytearray(ct)
                bad[i] ^= 0x80
                self.assertIsNone(d.open(n, b"hdr", bytes(bad)))
            self.assertIsNone(d.open(n, b"hdX", ct))

    def test_key_schedule_psk_changes_keys(self):
        a = kdf.KeySchedule("sha384", 32, None)
        b = kdf.KeySchedule("sha384", 32, os.urandom(32))
        self.assertNotEqual(a.handshake(b"s" * 64, b"t" * 48), b.handshake(b"s" * 64, b"t" * 48))


# ====================================================================== PKI

class TestPKICerts(unittest.TestCase):
    def test_roundtrip_and_pem(self):
        ident = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
        c = pki.Certificate.from_pem(ident.cert.to_pem())
        self.assertEqual(c, ident.cert)
        tp().trust().verify(c, pki.ROLE_CLIENT)

    def test_tampering_detected(self):
        cert = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"]).cert
        raw = bytearray(cert.encode())
        raw[30] ^= 1  # inside the subject / serial area
        try:
            forged = pki.Certificate.decode(bytes(raw))
        except pki.CertError:
            return
        with self.assertRaises(pki.CertError):
            tp().trust().verify(forged, pki.ROLE_CLIENT, subject=None)

    def test_role_subject_revocation_expiry(self):
        trust = tp().trust()
        srv = tp().identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"]).cert
        cli = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"]).cert
        with self.assertRaises(pki.CertError):
            trust.verify(srv, pki.ROLE_CLIENT)
        with self.assertRaises(pki.CertError):
            trust.verify(srv, pki.ROLE_SERVER, subject="evil.test")
        with self.assertRaises(pki.CertError):
            tp().trust(revoked={cli.serial_hex}).verify(cli, pki.ROLE_CLIENT)
        with self.assertRaises(pki.CertError):
            trust.verify(cli, pki.ROLE_CLIENT, now=time.time() + 3 * 86400)

    def test_foreign_ca_rejected(self):
        other = TestPKI(ca_alg="SLH-DSA-SHA2-128s")
        with self.assertRaises(pki.CertError):
            tp().trust().verify(other.identity(pki.ROLE_CLIENT, "mallory", ["10.66.0.9/32"]).cert,
                                pki.ROLE_CLIENT)

    def test_non_canonical_rejected(self):
        raw = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"]).cert.encode()
        with self.assertRaises(pki.CertError):
            pki.Certificate.decode(raw + b"\0")

    def test_key_mismatch(self):
        a = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
        with self.assertRaises(pki.CertError):
            pki.Identity(a.cert, tp().peer_alg.generate())

    def test_encrypted_private_key(self):
        key = tp().peer_alg.generate()
        pem = ossl.private_to_pem(key, b"correct horse")
        self.assertIn(b"ENCRYPTED", pem)
        self.assertEqual(ossl.raw_public(ossl.private_from_pem(pem, b"correct horse")), ossl.raw_public(key))
        with self.assertRaises(ossl.OpenSSLError):
            ossl.private_from_pem(pem, b"wrong")


# ====================================================================== wire / data plane units

class TestWire(unittest.TestCase):
    def test_fragmentation_roundtrip_out_of_order(self):
        body = os.urandom(CHUNK * 5 + 17)
        dgrams = fragment(MT_INIT, 7, 0, body)
        self.assertTrue(all(len(d) <= 1232 for d in dgrams))
        random.shuffle(dgrams)
        r, out = Reassembler(), None
        for d in dgrams + dgrams[:2]:  # duplicates are harmless
            hdr, payload = parse_hs(d)
            out = r.add(("k",), hdr, payload, 0) or out
        self.assertEqual(out, body)

    def test_parse_rejects_inconsistent(self):
        d = bytearray(fragment(MT_INIT, 7, 0, os.urandom(3000))[0])
        d[4] = 9  # fragment count inconsistent with total length
        with self.assertRaises(DecodeError):
            parse_hs(bytes(d))
        with self.assertRaises(DecodeError):
            parse_hs(b"\x01\x01")

    def test_replay_window(self):
        w = ReplayWindow(1 << 60)

        def accept(n):
            if w.check(n):
                w.update(n)
                return True
            return False

        self.assertTrue(accept(0))
        self.assertFalse(accept(0))
        self.assertTrue(accept(5))
        self.assertTrue(accept(3))
        self.assertFalse(accept(3))
        self.assertTrue(accept(5000))
        self.assertFalse(accept(5000 - 2048))      # fell out of the window
        self.assertTrue(accept(5000 - 2047))
        self.assertFalse(accept(1 << 60))          # beyond the hard limit

    def test_pad_unpad(self):
        pkt = icmp_echo("10.0.0.1", "10.0.0.2", 1, b"x" * 13)
        p = pad(pkt, 1420)
        self.assertEqual(len(p) % 16, 0)
        self.assertEqual(unpad(p), pkt)
        self.assertIsNone(unpad(b"\x99" * 40))

    def test_route_table_lpm(self):
        import ipaddress as ip
        rt = RouteTable()
        rt.insert(ip.ip_network("10.0.0.0/8"), "wide")
        rt.insert(ip.ip_network("10.1.2.3/32"), "host")
        rt.insert(ip.ip_network("fd00::/64"), "v6")
        self.assertEqual(rt.lookup(ip.ip_address("10.1.2.3")), "host")
        self.assertEqual(rt.lookup(ip.ip_address("10.9.9.9")), "wide")
        self.assertEqual(rt.lookup(ip.ip_address("fd00::5")), "v6")
        self.assertIsNone(rt.lookup(ip.ip_address("192.168.1.1")))

    def test_cookie(self):
        jar = CookieJar()
        c = jar.make("1.2.3.4", 5, 6, b"n" * 32, 0)
        self.assertTrue(jar.check(c, "1.2.3.4", 5, 6, b"n" * 32, 0))
        self.assertFalse(jar.check(c, "1.2.3.5", 5, 6, b"n" * 32, 0))
        jar._maybe_rotate(1e9)
        self.assertTrue(jar.check(c, "1.2.3.4", 5, 6, b"n" * 32, 1e9))  # previous secret still valid


# ====================================================================== handshake (state machines)

def _drive(initiator: Initiator, responder: Responder, tamper_init=None):
    """Run a handshake purely in memory; return (initiator_result, responder_result)."""
    addr = ("192.0.2.1", 4444)
    flight, hs, now = initiator.flight, None, time.monotonic()
    for _ in range(4):
        r = Reassembler()
        body = None
        for d in flight:
            hdr, payload = parse_hs(d)
            body = r.add(("i",), hdr, payload, now) or body
        if tamper_init:
            body = tamper_init(body)
        out, hs = responder.on_init(hdr, body, addr, now, require_cookie=False, taken_indices=set())
        if hs is not None:
            break
        rh, rb = parse_hs(out[0])
        flight = {5: initiator.on_retry, 6: initiator.on_cookie}[rh.msg_type](rh, rb)
    r = Reassembler()
    for d in out:
        rh, rp = parse_hs(d)
        body = r.add(("r",), rh, rp, now) or body
    auth_i = initiator.on_response(rh, body)
    res_r = None
    m4 = []
    for d in auth_i:
        h, p = parse_hs(d)
        f, rr = hs.on_auth_fragment(h, p, now)
        m4 += f
        res_r = rr or res_r
    res_i = None
    for d in m4:
        h, p = parse_hs(d)
        res_i = initiator.on_auth_fragment(h, p, now) or res_i
    return res_i, res_r


class TestHandshakeLogic(unittest.TestCase):
    def setUp(self):
        self.srv = tp().identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"])
        self.cli = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
        self.suites = tuple(SUITES_BY_NAME.values())

    def responder(self, suites=None, psk=None, trust=None):
        return Responder(self.srv, trust or tp().trust(), Policy(suites or self.suites, psk),
                         lambda c: {"addresses": list(c.addresses)})

    def test_keys_match(self):
        ri, rr = _drive(Initiator(self.cli, tp().trust(), Policy(self.suites), "vpn.test"), self.responder())
        self.assertEqual(ri.send_key, rr.recv_key)
        self.assertEqual(ri.recv_key, rr.send_key)
        self.assertNotEqual(ri.send_key, ri.recv_key)
        self.assertEqual(ri.peer_cert.subject, "vpn.test")
        self.assertEqual(rr.peer_cert.subject, "alice")

    def test_retry_negotiates_server_preference(self):
        s1 = SUITES_BY_NAME["MLKEM768-X25519_CHACHA20POLY1305_SHA384"]
        s3 = SUITES_BY_NAME["MLKEM1024-P384_AES256GCM_SHA384"]
        ini = Initiator(self.cli, tp().trust(), Policy((s3, s1)), "vpn.test")
        ri, rr = _drive(ini, self.responder(suites=(s1,)))
        self.assertEqual(ri.suite, s1)
        self.assertEqual(rr.suite, s1)

    def test_downgrade_of_offer_list_detected(self):
        """A MITM that strips suites from INIT breaks the transcript -> no session."""
        def strip(body):
            m = decode_init(body)
            m.offered = (m.share_suite,)
            return encode_init(m)
        ini = Initiator(self.cli, tp().trust(), Policy(self.suites), "vpn.test")
        ri, rr = _drive(ini, self.responder(), tamper_init=strip)
        self.assertIsNone(rr)
        self.assertIsNone(ri)

    def test_wrong_server_name(self):
        ini = Initiator(self.cli, tp().trust(), Policy(self.suites), "other.test")
        with self.assertRaises(HandshakeError):
            _drive(ini, self.responder())

    def test_psk_mismatch_and_match(self):
        psk = os.urandom(32)
        ri, rr = _drive(Initiator(self.cli, tp().trust(), Policy(self.suites, psk), "vpn.test"),
                        self.responder(psk=psk))
        self.assertIsNotNone(ri)
        ri, rr = _drive(Initiator(self.cli, tp().trust(), Policy(self.suites, os.urandom(32)), "vpn.test"),
                        self.responder(psk=psk))
        self.assertIsNone(rr)  # AUTH_I fails AEAD under the wrong handshake key

    def test_revoked_client(self):
        ini = Initiator(self.cli, tp().trust(), Policy(self.suites), "vpn.test")
        with self.assertRaises(HandshakeError):
            _drive(ini, self.responder(trust=tp().trust(revoked={self.cli.cert.serial_hex})))

    def test_server_cert_cannot_act_as_client(self):
        ini = Initiator(self.srv, tp().trust(), Policy(self.suites), "vpn.test")
        with self.assertRaises(HandshakeError):
            _drive(ini, self.responder())


# ====================================================================== end-to-end over UDP

class TestEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.nodes = []

    async def asyncTearDown(self):
        for n in self.nodes:
            n.close()
        await asyncio.sleep(0.05)  # let the transports finish closing

    async def pair(self, **kw):
        crypto = kw.pop("crypto", crypto_cfg())
        scfg = server_cfg(crypto, **kw.pop("server_kw", {}))
        server, client, s_tun, c_tun = await loopback_pair(tp(), scfg, **kw)
        self.nodes += [client, server]
        return server, client, s_tun, c_tun

    async def connect(self, client, timeout=10):
        client.start_handshake(time.monotonic())
        await asyncio.wait_for(client.connected.wait(), timeout)

    async def ping(self, c_tun, s_tun, seq=1):
        c_tun.inject(icmp_echo("10.66.0.2", "10.66.0.1", seq))
        return await asyncio.wait_for(s_tun.written.get(), 3)

    async def test_bidirectional_traffic(self):
        server, client, s_tun, c_tun = await self.pair()
        await self.connect(client)
        for i in range(50):
            pkt = icmp_echo("10.66.0.2", "10.66.0.1", i, os.urandom(random.randint(0, 1300)))
            c_tun.inject(pkt)
            self.assertEqual(await asyncio.wait_for(s_tun.written.get(), 3), pkt)
            back = icmp_echo("10.66.0.1", "10.66.0.2", i)
            s_tun.inject(back)
            self.assertEqual(await asyncio.wait_for(c_tun.written.get(), 3), back)

    async def test_staged_packets_flushed_after_connect(self):
        server, client, s_tun, c_tun = await self.pair()
        pkt = icmp_echo("10.66.0.2", "10.66.0.1", 7)
        c_tun.inject(pkt)  # no session yet: triggers handshake, packet staged
        self.assertEqual(await asyncio.wait_for(s_tun.written.get(), 10), pkt)

    async def test_replay_and_tamper_dropped(self):
        server, client, s_tun, c_tun = await self.pair()
        await self.connect(client)
        captured = []
        orig = client.transport.sendto
        client.transport.sendto = lambda d, a=None: (captured.append(d), orig(d, a))
        await self.ping(c_tun, s_tun)
        data = [d for d in captured if d[0] == PT_DATA][-1]
        server.datagram_received(data, ("127.0.0.1", client.transport.get_extra_info("sockname")[1]))
        bad = bytearray(data)
        bad[-1] ^= 1
        server.datagram_received(bytes(bad), ("127.0.0.1", 1))
        await asyncio.sleep(0.2)
        self.assertTrue(s_tun.written.empty(), "replayed/tampered packet reached the TUN")

    async def test_source_spoofing_blocked(self):
        server, client, s_tun, c_tun = await self.pair()
        await self.connect(client)
        c_tun.inject(icmp_echo("10.66.0.99", "10.66.0.1", 1))  # not alice's address
        c_tun.inject(icmp_echo("10.66.0.2", "10.66.0.1", 2))
        got = await asyncio.wait_for(s_tun.written.get(), 3)
        self.assertEqual(got[12:16], bytes([10, 66, 0, 2]))
        await asyncio.sleep(0.1)
        self.assertTrue(s_tun.written.empty())

    async def test_cookie_round_trip_under_load(self):
        server, client, s_tun, c_tun = await self.pair(server_kw={"always_require_cookie": True})
        await self.connect(client)
        await self.ping(c_tun, s_tun)

    async def test_lost_handshake_packets_recovered(self):
        server, client, s_tun, c_tun = await self.pair()
        dropped = {"n": 0}
        orig = server.transport.sendto

        def lossy(d, a=None):
            if d[0] == 0x01 and d[2] == 4 and dropped["n"] < 3:  # drop AUTH_R fragments
                dropped["n"] += 1
                return
            orig(d, a)
        server.transport.sendto = lossy
        await self.connect(client, timeout=15)
        self.assertEqual(dropped["n"], 3)
        await self.ping(c_tun, s_tun)

    async def test_rekey_keeps_traffic_flowing(self):
        server, client, s_tun, c_tun = await self.pair(crypto=crypto_cfg(rekey=2))
        await self.connect(client)
        first = client.peer.current.local_index
        await self.ping(c_tun, s_tun, 1)
        await asyncio.sleep(3.2)
        self.assertNotEqual(client.peer.current.local_index, first, "no rekey happened")
        for i in range(2, 6):
            await self.ping(c_tun, s_tun, i)

    async def test_roaming_follows_newest_packet_only(self):
        server, client, s_tun, c_tun = await self.pair()
        await self.connect(client)
        await self.ping(c_tun, s_tun)
        peer = server.peers["alice"]
        kp = client.peer.current
        old = kp.encrypt(b"")
        new = kp.encrypt(b"")
        server.datagram_received(new, ("127.0.0.1", 40000))
        self.assertEqual(peer.endpoint, ("127.0.0.1", 40000))
        server.datagram_received(old, ("127.0.0.1", 40001))  # older counter: must not redirect
        self.assertEqual(peer.endpoint, ("127.0.0.1", 40000))

    async def test_untrusted_client_rejected(self):
        other = TestPKI(ca_alg="SLH-DSA-SHA2-128s")
        mallory = other.identity(pki.ROLE_CLIENT, "mallory", ["10.66.0.2/32"])
        server, client, s_tun, c_tun = await self.pair(client_identity=mallory)
        client.start_handshake(time.monotonic())
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(client.connected.wait(), 2)
        self.assertEqual(server.peers, {})

    async def test_idle_client_detects_dead_server(self):
        """Keepalives are answered by the responder, so an idle client notices a dead server."""
        import pqvpn.node as node
        saved = (node.KEEPALIVE_TIMEOUT, node.REKEY_TIMEOUT)
        node.KEEPALIVE_TIMEOUT, node.REKEY_TIMEOUT = 1, 2  # compress the 10 s / 5 s timers
        try:
            server, client, s_tun, c_tun = await self.pair(ccfg_kw={"persistent_keepalive": 1})
            states = []
            client.on_state = lambda st, info: states.append(st)
            await self.connect(client)
            await asyncio.sleep(4)  # idle but alive: keepalives are acknowledged
            self.assertNotIn("reconnecting", states)
            server.close()
            for _ in range(40):
                await asyncio.sleep(0.25)
                if "reconnecting" in states:
                    break
            self.assertIn("reconnecting", states)

            # The server comes back on the same port: the client must recover by itself
            # and then stay connected (no spurious re-handshake from stale liveness state).
            import socket
            from pqvpn.tun import MemoryTun
            await asyncio.sleep(4)  # outage lasts longer than the liveness threshold (like a real restart)
            back = node.ServerNode(server.cfg, tp().identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"]),
                                   tp().trust(), MemoryTun("s2"))
            await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: back, sock=node.make_udp_socket("127.0.0.1", client.endpoint[1], socket.AF_INET))
            back.start_timers()
            self.nodes.append(back)
            outage = states.index("reconnecting")
            for _ in range(80):
                await asyncio.sleep(0.25)
                if "connected" in states[outage:]:
                    break
            await asyncio.sleep(4)
            self.assertEqual(states[outage:], ["reconnecting", "connected"],
                             "client must recover exactly once, without flapping")
        finally:
            node.KEEPALIVE_TIMEOUT, node.REKEY_TIMEOUT = saved

    async def test_icmp_unreachable_does_not_deafen_socket(self):
        """Regression: on Windows, WSAECONNRESET used to stop the UDP read loop."""
        server, client, s_tun, c_tun = await self.pair()
        await self.connect(client)
        for port in (9, 19, 29):
            server.transport.sendto(b"x", ("127.0.0.1", port))
            client.transport.sendto(b"x", ("127.0.0.1", port))
        await asyncio.sleep(0.3)
        await self.ping(c_tun, s_tun)
        s_tun.inject(icmp_echo("10.66.0.1", "10.66.0.2", 9))
        await asyncio.wait_for(c_tun.written.get(), 3)

    async def test_fuzzing_does_not_crash(self):
        server, client, s_tun, c_tun = await self.pair()
        await self.connect(client)
        rnd = random.Random(1)
        samples = list(client.hs.flight if client.hs else []) + [client.peer.current.encrypt(b"")]
        init = Initiator(client.identity, client.trust, client.policy, "vpn.test").flight
        samples += init
        with self.assertNoLogs("pqvpn", level="ERROR"):
            for _ in range(3000):
                base = bytearray(rnd.choice(samples)) if rnd.random() < 0.7 else bytearray(
                    os.urandom(rnd.randint(0, 1500)))
                for _ in range(rnd.randint(1, 8)):
                    if base:
                        base[rnd.randrange(len(base))] = rnd.randrange(256)
                server.datagram_received(bytes(base), ("127.0.0.1", rnd.randint(1, 65535)))
                client.datagram_received(bytes(base), client.endpoint)
        await self.ping(c_tun, s_tun)  # still healthy


if __name__ == "__main__":
    unittest.main()
