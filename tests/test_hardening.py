"""Phase 1 hardening (docs/AUDIT-2026-11.md): each test pins one change of that stage.

  * abuse limits per network (IPv4 address / IPv6 /64), a global cap on registrations, one CA signature at a time
  * 2FA seeds sealed at rest, bound to their account; an empty seed never verifies
  * server logs without clients' public addresses unless the operator opts in (privacy policy)
  * ${NAME} references in secret paths (systemd LoadCredential), failing closed when unset
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import pki  # noqa: E402
from pqvpn.config import ConfigError, load_server  # noqa: E402
from pqvpn.crypto.suites import sig_alg_by_name  # noqa: E402
from pqvpn.portal import auth, devices  # noqa: E402
from pqvpn.portal.devices import DeviceError  # noqa: E402
from pqvpn.portal.vault import Vault  # noqa: E402
from pqvpn.portal.web import Portal  # noqa: E402
from pqvpn.protocol import RateLimiter, source_key  # noqa: E402
from pqvpn.runner import TestPKI, crypto_cfg, loopback_pair, server_cfg  # noqa: E402
from tests import test_app_api  # noqa: E402  (module import: unittest must not collect TestAppApi again)
from tests.test_app_api import App  # noqa: E402

ML_DSA_65 = sig_alg_by_name("ML-DSA-65")
PASSWORD = test_app_api.TestAppApi.signup.__defaults__[0]


def public_key_b64() -> str:
    return base64.b64encode(ML_DSA_65.public_bytes(ML_DSA_65.generate())).decode()


class TestSourceKey(unittest.TestCase):
    def test_ipv6_counts_per_slash_64_and_ipv4_per_address(self):
        self.assertEqual(source_key("203.0.113.7"), "203.0.113.7")
        self.assertEqual(source_key("2001:db8:1:2::1"), "2001:db8:1:2::/64")
        self.assertEqual(source_key("2001:db8:1:2:ffff:ffff:ffff:ffff"), "2001:db8:1:2::/64")
        self.assertNotEqual(source_key("2001:db8:1:3::1"), source_key("2001:db8:1:2::1"))
        self.assertEqual(source_key("::ffff:198.51.100.4"), "198.51.100.4")    # dual-stack sockets
        self.assertEqual(source_key("fe80::1%eth0"), "fe80::/64")
        self.assertEqual(source_key("not-an-ip"), "not-an-ip")

    def test_rotating_ipv6_addresses_share_one_bucket(self):
        rl, now = RateLimiter(rate=0.001, burst=3), 1000.0
        allowed = [rl.allow(source_key(f"2001:db8:aa:bb::{i:x}"), now) for i in range(10)]
        self.assertEqual(allowed, [True] * 3 + [False] * 7)  # a fresh address per request buys nothing
        self.assertTrue(rl.allow(source_key("2001:db8:aa:cc::1"), now))  # another network still gets through


class TestEnrollmentAbuseLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_app_api.TestAppApi.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        test_app_api.TestAppApi.tearDownClass.__func__(cls)

    def setUp(self):
        self.portal.store.set_settings({**devices.APP_DEFAULTS, "app_enrollment": "1"})

    def enroll(self, ip: str):
        p = self.portal
        return devices.enroll(p.cfg, p.store, p.ca, p.settings(), "android", "ML-DSA-65", public_key_b64(), ip)

    def test_registrations_are_counted_per_ipv6_slash_64(self):
        self.portal.store.set_settings({"enroll_per_ip_day": "2"})
        device, _token, _cert = self.enroll("2001:db8:5:6::1")
        self.assertEqual(device["enroll_ip"], "2001:db8:5:6::/64")  # the network is kept, not the address
        self.enroll("2001:db8:5:6:dead:beef::9")
        with self.assertRaises(DeviceError) as cm:
            self.enroll("2001:db8:5:6:1234::77")  # a third address in the same /64
        self.assertEqual((cm.exception.status, cm.exception.code), (429, "rate_limited"))
        self.enroll("2001:db8:5:7::1")  # the neighbouring /64 is another network

    def test_global_hourly_cap(self):
        recent = self.portal.store.enrollments_since_any(int(time.time()) - 3600)
        self.portal.store.set_settings({"enroll_per_hour": str(recent + 1)})
        self.enroll("198.51.100.20")
        with self.assertRaises(DeviceError) as cm:
            self.enroll("198.51.100.21")  # another network, but the hour's budget is used up
        self.assertEqual((cm.exception.status, cm.exception.code), (429, "busy"))

    def test_one_ca_signature_at_a_time(self):
        real, active, peak, lock = pki.issue, [0], [0], threading.Lock()

        def slow_issue(**kw):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                time.sleep(0.05)
                return real(**kw)
            finally:
                with lock:
                    active[0] -= 1

        with mock.patch.object(pki, "issue", slow_issue):
            threads = [threading.Thread(target=self.enroll, args=(f"192.0.2.{i}",)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
        self.assertEqual(peak[0], 1)


class TestSealedTotp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_app_api.TestAppApi.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        test_app_api.TestAppApi.tearDownClass.__func__(cls)

    def setUp(self):
        self.portal.store.set_settings({**devices.APP_DEFAULTS, "app_enrollment": "1", "app_accounts": "1"})

    def settings(self, **values):  # used by the borrowed TestAppApi.signup
        self.portal.store.set_settings({k: str(v) for k, v in values.items()})

    def signed_in_app(self, email: str) -> tuple[App, dict]:
        app = App(self.port)
        app.enroll()
        test_app_api.TestAppApi.signup(self, app, email)
        return app, self.portal.store.user_by_email(email)

    def login(self, app: App, email: str, code: str = ""):
        return app.call("POST", "/api/v1/login", {"login": email, "password": PASSWORD, "code": code})

    def test_seed_is_sealed_and_still_verifies(self):
        app, user = self.signed_in_app("sealed-2fa@example.com")
        secret = auth.new_totp_secret()
        self.portal.store.update_user(user["id"], totp_secret=self.portal.seal_totp(user["id"], secret),
                                      totp_enabled=1)
        stored = self.portal.store.user(user["id"])["totp_secret"]
        self.assertTrue(Vault.is_sealed(stored))
        self.assertNotIn(secret, stored)
        self.assertEqual(self.login(app, "sealed-2fa@example.com")[1]["error"], "totp_required")
        st, me = self.login(app, "sealed-2fa@example.com", auth.hotp(secret, auth.totp_step()))
        self.assertEqual(st, 200, me)

    def test_plaintext_seeds_are_sealed_at_start_up(self):
        app, user = self.signed_in_app("legacy-2fa@example.com")
        secret = auth.new_totp_secret()
        self.portal.store.update_user(user["id"], totp_secret=secret, totp_enabled=1)  # as older versions stored it
        st, _ = self.login(app, "legacy-2fa@example.com", auth.hotp(secret, auth.totp_step() - 1))
        self.assertEqual(st, 200)  # a legacy plaintext seed keeps working until the next start
        Portal(self.portal.cfg)  # a portal start re-seals
        stored = self.portal.store.user(user["id"])["totp_secret"]
        self.assertTrue(Vault.is_sealed(stored))
        self.assertEqual(self.portal.totp_secret(self.portal.store.user(user["id"])), secret)

    def test_a_sealed_seed_does_not_open_on_another_account(self):
        _app_a, a = self.signed_in_app("seed-owner@example.com")
        app_b, b = self.signed_in_app("seed-thief@example.com")
        secret = auth.new_totp_secret()
        sealed = self.portal.seal_totp(a["id"], secret)
        self.portal.store.update_user(b["id"], totp_secret=sealed, totp_enabled=1)  # row copied by a DB attacker
        self.assertEqual(self.portal.totp_secret(self.portal.store.user(b["id"])), "")
        st, data = self.login(app_b, "seed-thief@example.com", auth.hotp(secret, auth.totp_step()))
        self.assertEqual((st, data["error"]), (401, "totp_invalid"))

    def test_an_empty_seed_never_verifies(self):
        step = auth.totp_step()
        self.assertIsNone(auth.verify_totp("", auth.hotp("", step), 0))  # HMAC under an empty key is public


class TestPrivacyOfServerLogs(unittest.IsolatedAsyncioTestCase):
    async def run_pair(self, log_addresses: bool) -> tuple[list[logging.LogRecord], int]:
        tp = TestPKI(ca_alg="ML-DSA-87")
        scfg = server_cfg(crypto_cfg(rekey=2), log_peer_addresses=log_addresses)
        records: list[logging.LogRecord] = []
        handler = logging.Handler(logging.DEBUG)
        handler.emit = records.append
        logger = logging.getLogger("pqvpn")
        old_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        server = client = None
        try:
            server, client, _s_tun, _c_tun = await loopback_pair(tp, scfg)
            client.start_handshake(time.monotonic())
            await asyncio.wait_for(client.connected.wait(), 10)
            first = client.peer.current.local_index
            deadline = time.monotonic() + 8
            while client.peer.current.local_index == first and time.monotonic() < deadline:
                await asyncio.sleep(0.2)  # wait for the first rekey
            await asyncio.sleep(0.3)
            return records, client.transport.get_extra_info("sockname")[1]
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
            for n in (client, server):
                if n is not None:
                    n.close()
            await asyncio.sleep(0.05)

    async def test_client_addresses_stay_out_of_the_log_by_default(self):
        records, client_port = await self.run_pair(log_addresses=False)
        lines = [(r.levelno, r.getMessage()) for r in records]
        self.assertFalse([m for _lvl, m in lines if f":{client_port}" in m], "a client's IP:port reached the log")
        self.assertTrue(any(lvl == logging.INFO and "peer alice connected" in m for lvl, m in lines), lines)
        rekeys = [lvl for lvl, m in lines if "peer alice rekeyed" in m]
        self.assertTrue(rekeys and all(lvl == logging.DEBUG for lvl in rekeys), lines)  # rekeys are not INFO

    async def test_operator_can_opt_in_to_addresses(self):
        records, client_port = await self.run_pair(log_addresses=True)
        self.assertTrue(any(f"127.0.0.1:{client_port}" in r.getMessage() for r in records))


SERVER_TOML = """
[server]
certificate = "server.crt"
private_key = "${PQVPN_TEST_CREDENTIALS}/server.key"
ca = ["ca.crt"]

[crypto]
psk_file = "${PQVPN_TEST_CREDENTIALS}/psk.key"

[security]
log_peer_addresses = true
"""


class TestSecretPathsFromEnvironment(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pqvpn-creds-")
        self.creds = os.path.join(self.dir, "credentials")
        os.makedirs(self.creds)
        with open(os.path.join(self.creds, "psk.key"), "w") as f:
            f.write(base64.b64encode(os.urandom(32)).decode())
        self.path = os.path.join(self.dir, "server.toml")
        with open(self.path, "w") as f:
            f.write(SERVER_TOML)

    def test_credentials_directory_is_expanded(self):
        with mock.patch.dict(os.environ, {"PQVPN_TEST_CREDENTIALS": self.creds}):
            cfg = load_server(self.path)
        self.assertEqual(cfg.private_key, os.path.normpath(os.path.join(self.creds, "server.key")))
        self.assertEqual(len(cfg.crypto.psk), 32)
        self.assertTrue(cfg.log_peer_addresses)
        self.assertEqual(cfg.certificate, os.path.normpath(os.path.join(self.dir, "server.crt")))  # plain paths

    def test_unset_variable_is_an_error(self):
        env = {k: v for k, v in os.environ.items() if k != "PQVPN_TEST_CREDENTIALS"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ConfigError, "PQVPN_TEST_CREDENTIALS is not set"):
                load_server(self.path)

    def test_default_keeps_addresses_out(self):
        with open(self.path, "w") as f:
            f.write(SERVER_TOML.replace("log_peer_addresses = true", "").replace("${PQVPN_TEST_CREDENTIALS}/", ""))
        with open(os.path.join(self.dir, "psk.key"), "w") as f:
            f.write(base64.b64encode(os.urandom(32)).decode())
        self.assertFalse(load_server(self.path).log_peer_addresses)


if __name__ == "__main__":
    unittest.main()
