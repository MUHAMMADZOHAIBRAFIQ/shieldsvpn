"""Windows/desktop Free-with-ads: the device helper (desktop_account.py) and the portal's web-ad page."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import desktop_account, pki  # noqa: E402
from pqvpn.portal import devices  # noqa: E402
from tests import test_app_api  # noqa: E402  (module import: unittest must not collect TestAppApi again)
from tests.test_portal import Browser  # noqa: E402


class TestDesktopAccount(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_app_api.TestAppApi.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        test_app_api.TestAppApi.tearDownClass.__func__(cls)

    def setUp(self):
        self.portal.store.set_settings({**devices.APP_DEFAULTS, "app_enrollment": "1", "web_ads_enabled": "1",
                                        "web_ads_test": "1", "reward_min_seconds": "5"})
        self.url = f"http://127.0.0.1:{self.port}/"
        self.dir = tempfile.mkdtemp(prefix="pqvpn-desktop-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def enroll(self) -> desktop_account.DesktopAccount:
        return desktop_account.DesktopAccount.enroll(self.url, allow_http=True,
                                                     data_dir=os.path.join(self.dir, "device"))

    def test_enrolled_pc_has_a_sealed_key_and_a_working_profile(self):
        acct = self.enroll()
        self.assertTrue(acct.exists())
        self.assertEqual(sorted(os.listdir(acct.dir)),
                         ["account.json", "ca.crt", "client.toml", "device.crt", "device.key"])  # no PSK for app devices
        with open(os.path.join(acct.dir, "device.key"), encoding="ascii") as f:
            self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", f.read())  # never a plain key on disk
        with open(os.path.join(acct.dir, "account.json"), encoding="utf-8") as f:
            state = json.load(f)
        prefix = "dpapi:" if sys.platform == "win32" else "plain:"
        self.assertTrue(state["token"].startswith(prefix) and state["key_passphrase"].startswith(prefix))
        cfg = desktop_account.load_config(acct.config_path)  # what the app and the tray use
        ident = pki.Identity.load(cfg.certificate, cfg.private_key, cfg.key_passphrase)
        self.assertTrue(devices.is_device_subject(ident.cert.subject))
        self.assertIsNone(cfg.crypto.psk)
        self.assertEqual(acct.me()["plan"], "free")
        self.assertEqual(self.portal.store.vpn_device_by_subject(ident.cert.subject)["platform"], "windows")
        old_serial = ident.cert.serial_hex
        self.portal.store._exec("UPDATE vpn_devices SET cert_expires = ? WHERE subject = ?",
                                (int(time.time()) + 86400, ident.cert.subject))  # due for renewal
        acct.renew()
        cfg2 = desktop_account.load_config(acct.config_path)
        new = pki.Identity.load(cfg2.certificate, cfg2.private_key, cfg2.key_passphrase)
        self.assertNotEqual(new.cert.serial_hex, old_serial)
        self.assertEqual(new.cert.addresses, ident.cert.addresses)
        self.assertIsNone(desktop_account.account_for_config(os.path.join(self.dir, "elsewhere", "client.toml")))

    def test_web_ad_page_grants_time_only_after_the_minimum_viewing_time(self):
        acct = self.enroll()
        url = acct.web_reward_url()
        nonce = re.fullmatch(r"http://127\.0\.0\.1:8800/reward/([A-Za-z0-9_-]+)", url).group(1)
        b = Browser(self.port)
        st, h, page = b.get(f"/reward/{nonce}")
        self.assertEqual(st, 200)
        self.assertIn(b"TEST AD", page)
        self.assertIn(b'src="/static/reward.js"', page)
        self.assertEqual(h["Content-Security-Policy"].count("paddle"), 0)  # the strict policy, not the pay page's
        st, _, page = b.post(f"/reward/{nonce}", {})
        self.assertEqual(st, 425)  # too soon: the server measures the time itself
        self.assertFalse(acct.me()["can_connect"])
        self.portal.store._exec("UPDATE reward_grants SET started_at = started_at - 10 WHERE nonce_hash = ?",
                                (devices.nonce_hash(nonce),))
        before = time.time()
        st, _, page = b.post(f"/reward/{nonce}", {})
        self.assertEqual(st, 200)
        self.assertIn(b"more minutes", page)
        me = acct.me()
        self.assertTrue(me["can_connect"])
        self.assertAlmostEqual(me["free_until"], before + 1800, delta=5)
        self.assertEqual(b.post(f"/reward/{nonce}", {})[0], 404)  # single use
        self.assertEqual(b.get("/reward/" + "x" * 32)[0], 404)
        st, _, _ = b.post(f"/reward/{nonce}", {}, headers={"Origin": "https://evil.example"})
        self.assertEqual(st, 403)  # cross-site form posts are refused like everywhere else

    def test_web_ads_need_the_switch_and_a_test_or_real_ad(self):
        acct = self.enroll()
        url = acct.web_reward_url()
        nonce = url.rsplit("/", 1)[1]
        self.portal.store.set_settings({"web_ads_test": "0"})
        b = Browser(self.port)
        st, _, page = b.get(f"/reward/{nonce}")
        self.assertIn(b"not set up", page)
        self.portal.store._exec("UPDATE reward_grants SET started_at = started_at - 10 WHERE nonce_hash = ?",
                                (devices.nonce_hash(nonce),))
        self.assertEqual(b.post(f"/reward/{nonce}", {})[0], 404)  # no ad shown, no time
        self.portal.store.set_settings({"web_ads_enabled": "0"})
        from pqvpn.account_client import PortalError
        with self.assertRaises(PortalError) as cm:
            acct.web_reward_url()
        self.assertEqual(cm.exception.code, "disabled")


if __name__ == "__main__":
    unittest.main()
