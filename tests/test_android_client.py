"""Tests for the Android integration layer (pqvpn/android_client.py).

The asyncio + file-descriptor tests (AndroidTun, Session end to end) need a POSIX event loop with
``add_reader`` and AF_UNIX datagram sockets, i.e. Linux/macOS -- the same primitives Android provides.
They are skipped on Windows; run them under WSL/Linux with PQVPN_LIBCRYPTO pointing at OpenSSL >= 3.5.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import android_client as ac  # noqa: E402
from pqvpn import pki  # noqa: E402
from pqvpn.crypto import ossl  # noqa: E402
from pqvpn.runner import TestPKI, client_cfg, crypto_cfg, icmp_echo, server_cfg  # noqa: E402

POSIX = sys.platform != "win32"
TP: TestPKI | None = None


def setUpModule():
    global TP
    TP = TestPKI(ca_alg="SLH-DSA-SHA2-128s")


def tp() -> TestPKI:
    assert TP is not None
    return TP


# ====================================================================== tunnel settings

class TestTunnelSettings(unittest.TestCase):
    def setUp(self):
        self.cert = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"]).cert
        self.push = {"addresses": ["10.66.0.2/24"], "routes": ["10.66.0.0/24"], "dns": ["10.66.0.1"],
                     "mtu": 1420, "rekey_interval": 120}

    def cfg(self, **kw):
        return client_cfg(crypto_cfg(), 51820, **kw)

    def test_split_tunnel_default(self):
        s = ac.tunnel_settings(self.push, self.cfg(), self.cert)
        self.assertEqual(s["addresses"], [{"address": "10.66.0.2", "prefix": 24}])
        self.assertEqual(s["routes"], [{"address": "10.66.0.0", "prefix": 24}])
        self.assertEqual(s["dns"], ["10.66.0.1"])
        self.assertFalse(s["full_tunnel"])
        self.assertEqual((s["bypass_families"], s["blocked_families"]), (["ipv6"], []))
        self.assertEqual(s["session"], "vpn.test")

    def test_full_tunnel_blocks_unconfigured_family(self):
        push = {**self.push, "dns": ["10.66.0.1", "2606:4700:4700::1111"]}
        s = ac.tunnel_settings(push, self.cfg(full_tunnel=True), self.cert)
        self.assertIn({"address": "0.0.0.0", "prefix": 0}, s["routes"])
        self.assertNotIn({"address": "::", "prefix": 0}, s["routes"])  # no IPv6 address: block instead
        self.assertTrue(s["full_tunnel"])
        self.assertEqual((s["blocked_families"], s["bypass_families"]), (["ipv6"], []))
        self.assertEqual(s["dns"], ["10.66.0.1"])  # an IPv6 resolver would re-enable the blocked family
        self.assertIn("2606:4700:4700::1111", s["dropped"])

    def test_server_pushed_default_route_is_full_tunnel(self):
        s = ac.tunnel_settings({**self.push, "routes": ["0.0.0.0/0"]}, self.cfg(), self.cert)
        self.assertTrue(s["full_tunnel"])
        self.assertEqual(s["blocked_families"], ["ipv6"])

    def test_full_tunnel_without_dns_fails_closed(self):
        """Regression (DNS leak found on the emulator): no DNS + full tunnel = lookups outside the VPN."""
        for push in ({**self.push, "dns": []}, {**self.push, "dns": ["2606:4700:4700::1111"]}):  # v6-only: unusable
            with self.assertRaisesRegex(ac.TunnelConfigError, "name lookups would bypass the VPN"):
                ac.tunnel_settings(push, self.cfg(full_tunnel=True), self.cert)
        with self.assertRaisesRegex(ac.TunnelConfigError, "bypass the VPN"):  # client opted out of server DNS
            ac.tunnel_settings(self.push, self.cfg(full_tunnel=True, use_server_dns=False), self.cert)
        with self.assertRaisesRegex(ac.TunnelConfigError, "bypass the VPN"):  # server-pushed default route
            ac.tunnel_settings({**self.push, "routes": ["0.0.0.0/0"], "dns": []}, self.cfg(), self.cert)
        s = ac.tunnel_settings(self.push, self.cfg(full_tunnel=True, dns=["10.66.0.53"]), self.cert)  # profile DNS ok
        self.assertEqual(s["dns"], ["10.66.0.53"])
        # Split tunnel keeps its documented behaviour: without VPN DNS, Android uses the normal resolver.
        self.assertEqual(ac.tunnel_settings({**self.push, "dns": []}, self.cfg(), self.cert)["dns"], [])

    def test_dual_stack(self):
        cert = tp().identity(pki.ROLE_CLIENT, "dual", ["10.66.0.7/32", "fd66::7/128"]).cert
        push = {**self.push, "addresses": ["10.66.0.7/24", "fd66::7/64"], "routes": ["10.66.0.0/24", "fd66::/64"]}
        s = ac.tunnel_settings(push, self.cfg(full_tunnel=True), cert)
        self.assertEqual(len(s["addresses"]), 2)
        self.assertIn({"address": "::", "prefix": 0}, s["routes"])
        self.assertEqual((s["blocked_families"], s["bypass_families"]), ([], []))

    def test_address_must_come_from_certificate(self):
        with self.assertRaisesRegex(ac.TunnelConfigError, "not an address in your certificate"):
            ac.tunnel_settings({**self.push, "addresses": ["10.66.0.99/24"]}, self.cfg(), self.cert)
        for bad in ([], None, ["not-an-ip"], "10.66.0.2/24"):
            with self.assertRaises(ac.TunnelConfigError):
                ac.tunnel_settings({**self.push, "addresses": bad}, self.cfg(), self.cert)
        with self.assertRaises(ac.TunnelConfigError):
            ac.tunnel_settings(None, self.cfg(), self.cert)

    def test_routes_and_dns_validation(self):
        with self.assertRaisesRegex(ac.TunnelConfigError, "invalid route"):
            ac.tunnel_settings({**self.push, "routes": ["10.0.0.0/8", "bogus"]}, self.cfg(), self.cert)
        with self.assertRaisesRegex(ac.TunnelConfigError, "no routes"):
            ac.tunnel_settings({**self.push, "routes": []}, self.cfg(), self.cert)
        with self.assertRaisesRegex(ac.TunnelConfigError, "invalid DNS"):
            ac.tunnel_settings({**self.push, "dns": ["dns.google"]}, self.cfg(), self.cert)
        with self.assertRaisesRegex(ac.TunnelConfigError, "too many routes"):
            ac.tunnel_settings({**self.push, "routes": [f"10.{i // 256}.{i % 256}.0/24" for i in range(300)]},
                               self.cfg(), self.cert)

    def test_profile_overrides_and_mtu(self):
        s = ac.tunnel_settings({**self.push, "mtu": 1300}, self.cfg(routes=["192.168.50.0/24"], dns=["9.9.9.9"]),
                               self.cert)
        self.assertEqual(s["routes"], [{"address": "192.168.50.0", "prefix": 24}])
        self.assertEqual(s["dns"], ["9.9.9.9"])
        self.assertEqual(s["mtu"], 1300)  # the smaller of profile (1420) and server MTU
        s = ac.tunnel_settings({**self.push, "mtu": 99999}, self.cfg(use_server_dns=False), self.cert)
        self.assertEqual((s["mtu"], s["dns"]), (1420, []))  # an out-of-range server MTU is ignored


# ====================================================================== profile import

class TestImportProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pqvpn.config import load_portal
        from pqvpn.portal import auth
        from pqvpn.portal.service import CA, issue_profile, portal_init
        from pqvpn.portal.store import Store
        auth.SCRYPT_N = 1 << 14
        cls.tmp = tempfile.mkdtemp(prefix="pqvpn-android-")
        portal_init(os.path.join(cls.tmp, "portal"), server_name="vpn.test", endpoint="vpn.example.com:51820",
                    subnet="10.98.0.0/24", admin="root", listen=["127.0.0.1:8800"],
                    public_url="https://127.0.0.1:8800/", issuer="Test VPN", psk=True, nat="",
                    ca_alg="SLH-DSA-SHA2-128s")
        cfg = load_portal(os.path.join(cls.tmp, "portal", "portal.toml"))
        store = Store(cfg.database)
        ca = CA(cfg)
        for name in ("alice", "bob"):
            store.create_user(name, "user", "a long passphrase here")
        cls.zip_alice, cls.cert_alice = issue_profile(cfg, store, ca, store.user_by_name("alice"))
        cls.ca = ca
        cls.zip_bob, _ = issue_profile(cfg, store, ca, store.user_by_name("bob"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def dest(self) -> str:
        return tempfile.mkdtemp(dir=self.tmp)

    @staticmethod
    def rezip(src: bytes, change: dict) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(src)) as zin, zipfile.ZipFile(out, "w") as zout:
            names = zin.namelist()
            for n in names:
                base = n.rsplit("/", 1)[-1]
                if base in change:
                    if change[base] is not None:
                        zout.writestr(n, change[base])
                else:
                    zout.writestr(n, zin.read(n))
            for base, data in change.items():
                if data is not None and not any(n.endswith("/" + base) for n in names):
                    zout.writestr("pqvpn-alice/" + base, data)
        return out.getvalue()

    @staticmethod
    def member(src: bytes, base: str) -> bytes:
        with zipfile.ZipFile(io.BytesIO(src)) as z:
            return z.read(next(n for n in z.namelist() if n.endswith("/" + base)))

    def test_import_valid_portal_profile(self):
        d = self.dest()
        res = ac.import_profile(self.zip_alice, d)
        s = res["summary"]
        self.assertEqual((s["account"], s["server"], s["server_name"]), ("alice", "vpn.example.com:51820", "vpn.test"))
        self.assertEqual(s["tunnel_address"], self.cert_alice.addresses[0])
        self.assertFalse(s["full_tunnel"])
        self.assertEqual(sorted(os.listdir(d)), ["alice.crt", "ca.crt", "client.toml"])  # no key, no PSK on disk
        with open(os.path.join(d, "client.toml"), encoding="utf-8") as f:
            self.assertNotIn("psk_file", f.read())
        self.assertTrue(res["secrets"]["key_pem"].startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertEqual(len(base64.b64decode(res["secrets"]["psk"])), 32)
        self.assertEqual(ac.load_profile_summary(d)["account"], "alice")
        self.assertEqual(json.loads(ac.load_profile_summary_json(d))["summary"]["account"], "alice")
        bad = json.loads(ac.import_profile_json(b"not a zip", self.dest()))
        self.assertEqual((bad["ok"], "not a ZIP" in bad["error"]), (False, True))

        # The stored parts + secrets give a loadable session (key matches, PSK restored, cert trusted).
        session = ac.Session(d, res["secrets"]["key_pem"], res["secrets"]["psk"], bridge=None)
        cfg, identity, _trust = session._load()
        self.assertEqual(cfg.crypto.psk, base64.b64decode(res["secrets"]["psk"]))
        self.assertEqual(identity.cert.subject, "alice")
        self.assertEqual(session._key_pem, "")  # the PEM string is dropped once loaded

    def test_rejects_bad_files(self):
        with self.assertRaisesRegex(ac.ProfileError, "not a ZIP"):
            ac.import_profile(b"PK\x03\x04 nope", self.dest())
        with self.assertRaisesRegex(ac.ProfileError, "incomplete"):
            ac.import_profile(self.rezip(self.zip_alice, {"alice.key": None}), self.dest())
        with self.assertRaisesRegex(ac.ProfileError, "exactly one client.toml"):
            two = self.rezip(self.zip_alice, {})
            out = io.BytesIO(two)
            with zipfile.ZipFile(out, "a") as z:
                z.writestr("other/client.toml", "x")
            ac.import_profile(out.getvalue(), self.dest())
        toml = self.member(self.zip_alice, "client.toml").decode()
        traversal = toml.replace('certificate = "alice.crt"', 'certificate = "../../etc/alice.crt"')
        with self.assertRaisesRegex(ac.ProfileError, "must name a file inside the profile"):
            ac.import_profile(self.rezip(self.zip_alice, {"client.toml": traversal}), self.dest())
        with self.assertRaisesRegex(ac.ProfileError, "too large"):
            ac.import_profile(b"\0" * (ac.MAX_PROFILE_ZIP + 1), self.dest())

    def test_rejects_expired_certificate(self):
        """A certificate correctly signed by the profile's own CA but past its validity is refused at import."""
        alg = self.cert_alice.key_alg
        key = alg.generate()
        expired = pki.issue(role=pki.ROLE_CLIENT, subject="alice", key_alg=alg, public_key=alg.public_bytes(key),
                            addresses=list(self.cert_alice.addresses), days=1, issuer_key=self.ca.key,
                            issuer_alg=self.ca.cert.key_alg, issuer_public=self.ca.cert.public_key,
                            not_before=int(time.time()) - 10 * 86400)
        bad = self.rezip(self.zip_alice, {"alice.crt": expired.to_pem(), "alice.key": ossl.private_to_pem(key)})
        with self.assertRaisesRegex(ac.ProfileError, "expired"):
            ac.import_profile(bad, self.dest())

    def test_rejects_mismatched_key_and_foreign_ca(self):
        bob_key = self.member(self.zip_bob, "bob.key")
        with self.assertRaisesRegex(ac.ProfileError, "certificate is not usable"):
            ac.import_profile(self.rezip(self.zip_alice, {"alice.key": bob_key}), self.dest())
        foreign = TestPKI(ca_alg="SLH-DSA-SHA2-128s").ca_cert.to_pem()
        with self.assertRaisesRegex(ac.ProfileError, "certificate is not usable"):
            ac.import_profile(self.rezip(self.zip_alice, {"ca.crt": foreign}), self.dest())
        with self.assertRaisesRegex(ac.ProfileError, "psk.key"):
            ac.import_profile(self.rezip(self.zip_alice, {"psk.key": "not base64!!"}), self.dest())


# ====================================================================== TUN adapter + session

class FakeBridge:
    """Stands in for the Kotlin PythonVpnBridge: an AF_UNIX datagram pair plays the VPN TUN fd."""

    def __init__(self, fail_establish: bool = False):
        self.states: list[tuple[str, dict]] = []
        self.protected: list[int] = []
        self.settings: dict | None = None
        self.device: socket.socket | None = None   # "the OS side" of the TUN
        self.tun_fd = -1
        self.fail_establish = fail_establish
        self.cv = threading.Condition()

    def protectSocket(self, fd):
        self.protected.append(fd)
        return True

    def establishTunnel(self, settings_json):
        self.settings = json.loads(settings_json)
        if self.fail_establish:
            return -1
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.device = a
        self.tun_fd = b.detach()  # like ParcelFileDescriptor.detachFd(): the session owns it now
        return self.tun_fd

    def onState(self, state, info_json):
        with self.cv:
            self.states.append((state, json.loads(info_json)))
            self.cv.notify_all()

    def wait_for(self, state: str, timeout: float = 15) -> dict:
        with self.cv:
            ok = self.cv.wait_for(lambda: any(s == state for s, _ in self.states), timeout)
            if not ok:
                raise AssertionError(f"state {state!r} not reached; got {[s for s, _ in self.states]}")
            return next(i for s, i in self.states if s == state)


class TestNetworkChange(unittest.TestCase):
    """Session._on_network_changed against a stand-in node (the real path is covered end to end below)."""

    class Node:
        def __init__(self, hs):
            self.hs, self.hs_rto, self.next_attempt = hs, 8.0, 99.0
            self.closed = threading.Event()
            self.calls = []

        def start_handshake(self, now):
            self.calls.append("start")

        def _send_flight(self, now):
            self.calls.append("resend")

    def test_idle_session_starts_a_handshake(self):
        s = ac.Session("x", "", "", bridge=None)
        s.node = self.Node(hs=None)
        s._on_network_changed()
        self.assertEqual((s.node.calls, s.node.next_attempt), (["start"], 0.0))

    def test_handshake_in_flight_is_resent_immediately(self):
        s = ac.Session("x", "", "", bridge=None)
        s.node = self.Node(hs=object())
        s._on_network_changed()
        self.assertEqual((s.node.calls, s.node.hs_rto), (["resend"], 1.0))

    def test_closed_node_is_left_alone(self):
        s = ac.Session("x", "", "", bridge=None)
        s.node = self.Node(hs=None)
        s.node.closed.set()
        s._on_network_changed()
        self.assertEqual(s.node.calls, [])


class TestAndroidTunBasics(unittest.TestCase):
    def test_stats_before_connect(self):
        self.assertEqual(json.loads(ac.Session("x", "", "", bridge=None).stats_json()),
                         {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0})

    def test_black_hole_before_attach(self):
        t = ac.AndroidTun(1420)
        t.write(b"\x45" + bytes(19))
        self.assertEqual(t.dropped, 1)
        t.close()
        t.close()  # idempotent


@unittest.skipUnless(POSIX, "needs a POSIX event loop and AF_UNIX datagram sockets (Linux/Android)")
class TestSessionEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from pqvpn.node import ServerNode, make_udp_socket
        from pqvpn.tun import MemoryTun
        self.tmp = tempfile.mkdtemp(prefix="pqvpn-android-e2e-")
        loop = asyncio.get_running_loop()
        self.s_tun = MemoryTun("s")
        srv_id = tp().identity(pki.ROLE_SERVER, "vpn.test", ["10.66.0.1/24"])
        self.server = ServerNode(server_cfg(crypto_cfg()), srv_id, tp().trust(), self.s_tun)
        tr, _ = await loop.create_datagram_endpoint(lambda: self.server,
                                                    sock=make_udp_socket("127.0.0.1", 0, socket.AF_INET))
        self.s_tun.start(loop, self.server.on_tun_packets)
        self.server.start_timers()
        port = tr.get_extra_info("sockname")[1]
        cli = tp().identity(pki.ROLE_CLIENT, "alice", ["10.66.0.2/32"])
        self.key_pem = ossl.private_to_pem(cli.key).decode()
        with open(os.path.join(self.tmp, "alice.crt"), "w") as f:
            f.write(cli.cert.to_pem())
        with open(os.path.join(self.tmp, "ca.crt"), "w") as f:
            f.write(tp().ca_cert.to_pem())
        with open(os.path.join(self.tmp, "client.toml"), "w") as f:
            f.write(f"""[client]
server = "127.0.0.1:{port}"
server_name = "vpn.test"
certificate = "alice.crt"
private_key = "alice.key"
ca = ["ca.crt"]
[tunnel]
persistent_keepalive = 0
[crypto]
suites = ["MLKEM768-X25519_CHACHA20POLY1305_SHA384"]
ca_signature_algorithms = ["SLH-DSA-SHA2-128s"]
""")

    async def asyncTearDown(self):
        self.server.close()
        await asyncio.sleep(0.05)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def start(self, bridge):
        session = ac.Session(self.tmp, self.key_pem, "", bridge)
        task = asyncio.ensure_future(asyncio.to_thread(session.run))
        return session, task

    async def test_connect_traffic_network_change_and_cleanup(self):
        bridge = FakeBridge()
        session, task = await self.start(bridge)
        info = await asyncio.to_thread(bridge.wait_for, "connected")
        self.assertEqual(len(bridge.protected), 1)  # the UDP socket was exempted before any traffic
        self.assertEqual(bridge.settings["addresses"], [{"address": "10.66.0.2", "prefix": 24}])
        self.assertEqual(bridge.settings["routes"], [{"address": "10.66.0.0", "prefix": 24}])
        self.assertEqual(info["tunnel_address"], "10.66.0.2/24")
        self.assertIn("MLKEM768", info["suite"])
        states = [s for s, _ in bridge.states]
        self.assertLess(states.index("connecting"), states.index("connected"))

        # Device -> tunnel -> server, and back.
        pkt = icmp_echo("10.66.0.2", "10.66.0.1", 1, b"from android")
        bridge.device.send(pkt)
        self.assertEqual(await asyncio.wait_for(self.s_tun.written.get(), 5), pkt)
        reply = icmp_echo("10.66.0.1", "10.66.0.2", 2, b"to android")
        self.s_tun.inject(reply)
        bridge.device.setblocking(False)
        got = None
        for _ in range(50):
            try:
                got = bridge.device.recv(65535)
                break
            except BlockingIOError:
                await asyncio.sleep(0.1)
        self.assertEqual(got, reply)
        bridge.device.send(b"\x60" + bytes(39))  # IPv6 packet on an IPv4-only tunnel: dropped locally
        await asyncio.sleep(0.2)
        self.assertTrue(self.s_tun.written.empty())

        stats = json.loads(session.stats_json())  # what the UI polls for its traffic counters
        self.assertGreaterEqual(stats["tx_bytes"], len(pkt))   # the packet sent through the tunnel
        self.assertGreaterEqual(stats["rx_bytes"], len(reply))  # the reply that came back
        self.assertGreaterEqual((stats["tx_packets"], stats["rx_packets"]), (1, 1))

        # A network switch forces a fresh handshake on the same TUN.
        first = session.node.peer.current.local_index
        session.network_changed()
        for _ in range(100):
            await asyncio.sleep(0.1)
            if session.node.peer.current.local_index != first:
                break
        self.assertNotEqual(session.node.peer.current.local_index, first)
        bridge.device.send(pkt)
        self.assertEqual(await asyncio.wait_for(self.s_tun.written.get(), 5), pkt)

        session.stop()
        self.assertEqual(await asyncio.wait_for(task, 10), "")
        self.assertEqual(bridge.states[-1][0], "disconnected")
        with self.assertRaises(OSError):
            os.fstat(bridge.tun_fd)  # the TUN descriptor was closed -> Android tears the interface down
        self.assertTrue(session.tun.closed)

    async def test_establish_failure_stops_cleanly(self):
        bridge = FakeBridge(fail_establish=True)
        session, task = await self.start(bridge)
        message = await asyncio.wait_for(task, 20)
        self.assertIn("did not create the VPN interface", message)
        self.assertIn("error", [s for s, _ in bridge.states])
        self.assertEqual(bridge.states[-1], ("disconnected", {"message": message}))

    async def test_missing_or_wrong_credentials(self):
        other = tp().identity(pki.ROLE_CLIENT, "mallory", ["10.66.0.9/32"])
        bridge = FakeBridge()
        session = ac.Session(self.tmp, ossl.private_to_pem(other.key).decode(), "", bridge)
        message = await asyncio.wait_for(asyncio.to_thread(session.run), 10)
        self.assertIn("does not match the profile", message)
        self.assertEqual(bridge.protected, [])  # nothing was opened
        os.remove(os.path.join(self.tmp, "client.toml"))
        message = await asyncio.wait_for(asyncio.to_thread(ac.Session(self.tmp, self.key_pem, "", bridge).run), 10)
        self.assertIn("profile is damaged", message)

    async def test_stop_before_connect(self):
        bridge = FakeBridge()
        session = ac.Session(self.tmp, self.key_pem, "", bridge)
        session.stop()
        self.assertEqual(await asyncio.wait_for(asyncio.to_thread(session.run), 10), "")
        self.assertEqual(bridge.protected, [])


if __name__ == "__main__":
    unittest.main()
