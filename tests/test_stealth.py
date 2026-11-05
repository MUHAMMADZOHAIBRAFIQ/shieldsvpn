"""Stealth mode: the obfuscation layer (pqvpn/obfs.py) and its wiring into the node and config (PROTOCOL.md §8)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.config import ConfigError, load_client, load_server  # noqa: E402
from pqvpn.obfs import MIN_WIRE, Obfuscator, derive_key  # noqa: E402
from pqvpn.runner import TestPKI, crypto_cfg, icmp_echo, loopback_pair, server_cfg  # noqa: E402

KEY = os.urandom(32)


class TestObfuscator(unittest.TestCase):
    def setUp(self):
        self.o = Obfuscator(KEY)

    def test_round_trip_every_size(self):
        for n in (0, 1, 16, 40, 1216, 1452, 65535):
            data = os.urandom(n)
            self.assertEqual(self.o.unwrap(self.o.wrap(data)), data)

    def test_wrapping_hides_the_bytes_and_varies(self):
        data = bytes([0x01]) + b"handshake-looking inner datagram"
        a, b = self.o.wrap(data), self.o.wrap(data)
        self.assertNotEqual(a, b)            # fresh nonce every time
        self.assertNotIn(data, a)            # the inner bytes do not appear in clear
        self.assertNotEqual(a[0], 0x01)      # no fixed packet-type byte on the wire

    def test_handshake_fragment_fits_the_ipv6_minimum_mtu(self):
        for _ in range(200):
            self.assertLessEqual(len(self.o.wrap(os.urandom(1216))), 1280)

    def test_unauthenticated_input_is_dropped(self):
        self.assertIsNone(self.o.unwrap(b""))
        self.assertIsNone(self.o.unwrap(os.urandom(MIN_WIRE - 1)))
        self.assertIsNone(self.o.unwrap(os.urandom(200)))            # random: a probe
        self.assertIsNone(Obfuscator(os.urandom(32)).unwrap(self.o.wrap(b"hello")))  # wrong key
        wire = bytearray(self.o.wrap(b"hello"))
        wire[-1] ^= 1
        self.assertIsNone(self.o.unwrap(bytes(wire)))                # tampered tag

    def test_key_is_derived_not_used_raw(self):
        self.assertEqual(len(derive_key(KEY)), 32)
        self.assertEqual(derive_key(KEY), derive_key(KEY))
        self.assertNotEqual(derive_key(KEY), KEY)
        self.assertNotEqual(derive_key(KEY), derive_key(os.urandom(32)))


class TestStealthConfig(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pqvpn-stealth-")
        import base64
        self.key_b64 = base64.b64encode(KEY).decode()
        with open(os.path.join(self.dir, "obfs.key"), "w") as f:
            f.write(self.key_b64 + "\n")

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    SERVER = ('[server]\nlisten = "0.0.0.0:443"\ncertificate = "s.crt"\nprivate_key = "s.key"\nca = ["ca.crt"]\n'
              '[stealth]\n{stealth}\n')
    CLIENT = ('[client]\nserver = "vpn.test:443"\nserver_name = "vpn.test"\ncertificate = "c.crt"\n'
              'private_key = "c.key"\nca = ["ca.crt"]\n[stealth]\n{stealth}\n')

    def test_server_and_client_load_the_same_key(self):
        s = load_server(self.write("server.toml", self.SERVER.format(stealth='key_file = "obfs.key"')))
        c = load_client(self.write("client.toml", self.CLIENT.format(stealth='key_file = "obfs.key"')))
        self.assertEqual(s.obfuscation_key, KEY)
        self.assertEqual(c.obfuscation_key, KEY)

    def test_off_when_absent_or_disabled(self):
        s = load_server(self.write("server.toml", self.SERVER.format(stealth="")))
        self.assertIsNone(s.obfuscation_key)
        s2 = load_server(self.write("s2.toml", self.SERVER.format(stealth='key_file = "obfs.key"\nenabled = false')))
        self.assertIsNone(s2.obfuscation_key)

    def test_bad_key_is_a_config_error(self):
        with open(os.path.join(self.dir, "bad.key"), "w") as f:
            f.write("this is not base64 !!!")
        with self.assertRaisesRegex(ConfigError, "base64"):
            load_server(self.write("server.toml", self.SERVER.format(stealth='key_file = "bad.key"')))


class TestStealthEndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.nodes = []
        self.tp = TestPKI(ca_alg="ML-DSA-87")  # fast CA for the test PKI

    async def asyncTearDown(self):
        for n in self.nodes:
            n.close()
        await asyncio.sleep(0.05)

    async def pair(self, server_key, client_key):
        scfg = server_cfg(crypto_cfg())
        server, client, s_tun, c_tun = await loopback_pair(self.tp, scfg)
        self.nodes += [client, server]
        if server_key is not None:
            server.set_obfuscator(Obfuscator(server_key))
        if client_key is not None:
            client.set_obfuscator(Obfuscator(client_key))
        return server, client, s_tun, c_tun

    async def test_matching_keys_connect_and_pass_traffic(self):
        server, client, s_tun, c_tun = await self.pair(KEY, KEY)
        client.start_handshake(time.monotonic())
        await asyncio.wait_for(client.connected.wait(), 10)
        c_tun.inject(icmp_echo("10.66.0.2", "10.66.0.1", 1))
        got = await asyncio.wait_for(s_tun.written.get(), 3)
        self.assertEqual(got[12:16], ipaddress.IPv4Address("10.66.0.2").packed)

    async def test_no_connection_when_only_the_client_obfuscates(self):
        _server, client, _s_tun, _c_tun = await self.pair(None, KEY)
        client.start_handshake(time.monotonic())
        with self.assertRaises(asyncio.TimeoutError):   # the plain server drops the obfuscated INIT
            await asyncio.wait_for(client.connected.wait(), 2)

    async def test_no_connection_on_a_key_mismatch(self):
        _server, client, _s_tun, _c_tun = await self.pair(os.urandom(32), KEY)
        client.start_handshake(time.monotonic())
        with self.assertRaises(asyncio.TimeoutError):   # the server cannot unwrap the client's datagrams
            await asyncio.wait_for(client.connected.wait(), 2)


class TestStealthIssuance(unittest.TestCase):
    """The portal copies its obfuscation key into every issued profile (admin ZIP, app bundle) and portal-init."""

    @classmethod
    def setUpClass(cls):
        import base64
        from pqvpn.config import load_portal
        from pqvpn.portal import auth
        from pqvpn.portal.service import CA, portal_init
        from pqvpn.portal.store import Store
        auth.SCRYPT_N = 1 << 14
        cls.dir = tempfile.mkdtemp(prefix="pqvpn-stealth-issue-")
        portal_init(cls.dir, server_name="vpn.test", endpoint="vpn.test:443", subnet="10.70.0.0/24", admin="root",
                    listen=["127.0.0.1:8800"], public_url="https://vpn.test/", issuer="Test VPN", psk=False, nat="",
                    ca_alg="ML-DSA-87", stealth=True)
        cls.b64 = base64
        cls.cfg = load_portal(os.path.join(cls.dir, "portal.toml"))
        cls.ca = CA(cls.cfg)
        cls.store = Store(os.path.join(cls.dir, "portal.db"))

    def test_portal_init_turns_on_stealth_on_both_sides(self):
        from pqvpn.config import load_server
        s = load_server(os.path.join(self.dir, "server.toml"))
        self.assertIsNotNone(s.obfuscation_key)
        self.assertEqual(len(s.obfuscation_key), 32)
        self.assertEqual(self.cfg.obfuscation_key, s.obfuscation_key)  # server and portal share one key

    def test_admin_profile_zip_carries_the_key(self):
        import io
        import zipfile
        from pqvpn.config import load_client
        from pqvpn.portal.service import issue_profile
        uid = self.store.create_user("alice", "user", "correct horse battery")
        data, _cert = issue_profile(self.cfg, self.store, self.ca, self.store.user(uid))
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = {n.split("/", 1)[1] for n in z.namelist() if "/" in n}
            self.assertIn("obfs.key", names)
            toml = z.read("pqvpn-alice/client.toml").decode()
            self.assertIn('key_file = "obfs.key"', toml)
            out = tempfile.mkdtemp(prefix="pqvpn-prof-")
            for n in z.namelist():
                base = n.split("/", 1)[1] if "/" in n else n
                if base:
                    with open(os.path.join(out, base), "wb") as f:
                        f.write(z.read(n))
        self.assertEqual(load_client(os.path.join(out, "client.toml")).obfuscation_key, self.cfg.obfuscation_key)

    def test_app_bundle_carries_the_key(self):
        from pqvpn import pki
        from pqvpn.crypto.suites import sig_alg_by_name
        from pqvpn.portal import devices
        alg = sig_alg_by_name(self.cfg.client_algorithm)
        k = alg.generate()
        cert = pki.issue(role=pki.ROLE_CLIENT, subject="d-" + "a" * 24, key_alg=alg, public_key=alg.public_bytes(k),
                         addresses=["10.70.0.9/32"], days=1, issuer_key=self.ca.key, issuer_alg=self.ca.cert.key_alg,
                         issuer_public=self.ca.cert.public_key)
        bundle = devices.bundle(self.cfg, self.ca, {"subject": "d-" + "a" * 24, "vpn_ip": "10.70.0.9"}, cert)
        self.assertEqual(self.b64.b64decode(bundle["obfuscation_key"]), self.cfg.obfuscation_key)
        self.assertEqual(bundle["psk"], "")  # app devices still get no PSK

    def test_android_import_writes_the_obfs_key_as_a_file(self):
        import io
        import json
        import zipfile
        from pqvpn import android_client
        from pqvpn.config import load_client
        from pqvpn.portal.service import issue_profile
        uid = self.store.create_user("bob", "user", "correct horse battery")
        data, _cert = issue_profile(self.cfg, self.store, self.ca, self.store.user(uid))
        with zipfile.ZipFile(io.BytesIO(data)) as z:  # sanity: the ZIP is the one we think
            self.assertIn("pqvpn-bob/obfs.key", z.namelist())
        dest = tempfile.mkdtemp(prefix="pqvpn-android-")
        os.rmdir(dest)  # import_profile wants to create it
        result = json.loads(android_client.import_profile_json(data, dest))
        self.assertTrue(result["ok"], result)
        self.assertTrue(os.path.isfile(os.path.join(dest, "obfs.key")))   # kept as a file, not sealed
        self.assertEqual(load_client(os.path.join(dest, "client.toml")).obfuscation_key, self.cfg.obfuscation_key)


if __name__ == "__main__":
    unittest.main()
