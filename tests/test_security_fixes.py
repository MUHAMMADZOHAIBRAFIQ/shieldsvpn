"""Regression tests for the security review of 2026-10-30: each test pins one fixed vulnerability."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.crypto import ossl  # noqa: E402
from pqvpn.portal import auth, devices, firebase, play, rewards  # noqa: E402
from pqvpn.portal.store import Store  # noqa: E402
from tests import test_app_api  # noqa: E402  (module import: unittest must not collect TestAppApi again)
from tests.fake_firestore import FakeGoogle, make_key  # noqa: E402
from tests.test_app_api import App  # noqa: E402

PACKAGE, PRODUCT = "com.shieldsvpn.vpn", "shieldsvpn_pro"
PASSWORD = test_app_api.TestAppApi.signup.__defaults__[0]


class TestAccountIdsAreNeverReused(unittest.TestCase):
    def test_store_skips_deleted_ids(self):
        s = Store(os.path.join(tempfile.mkdtemp(prefix="pqvpn-ids-"), "t.db"))
        with mock.patch.object(auth, "SCRYPT_N", 1 << 10):
            a = s.create_user("alice", "user", "x" * 12)
            b = s.create_user("bob", "user", "x" * 12)
            s.delete_user(b)          # the newest account: SQLite alone would hand its id out again
            c = s.create_user("carol", "user", "x" * 12)
            s.delete_user(a)
            d = s.create_user("dave", "user", "x" * 12)
        self.assertGreater(c, b)
        self.assertGreater(d, c)
        self.assertEqual(len({a, b, c, d}), 4)


class TestSecurityLogRetention(unittest.TestCase):
    def test_entries_older_than_a_year_are_forgotten(self):
        from pqvpn.portal import access
        s = Store(os.path.join(tempfile.mkdtemp(prefix="pqvpn-audit-"), "t.db"))
        s.audit("login_ok", actor="old")
        s.audit("login_ok", actor="recent")
        s._exec("UPDATE audit SET ts = ? WHERE actor = 'old'", (int(time.time()) - access.AUDIT_RETENTION - 60,))
        self.assertEqual(s.purge_audit(access.AUDIT_RETENTION), 1)
        self.assertEqual([r["actor"] for r in s.audit_after(0, 10)], ["recent"])


class TestPortalFixes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_app_api.TestAppApi.setUpClass.__func__(cls)
        cls.google = FakeGoogle()
        cls.key, pkey = make_key()
        cls.google.trust(cls.key, pkey)
        cls.portal.play.client_factory = lambda key: play.PlayClient(key, api=cls.google.play_api,
                                                                     token_uri=f"{cls.google.url}/token")

    @classmethod
    def tearDownClass(cls):
        cls.google.stop()
        test_app_api.TestAppApi.tearDownClass.__func__(cls)

    def setUp(self):
        self.portal.store.set_settings({**devices.APP_DEFAULTS, **play.DEFAULT_SETTINGS, "app_enrollment": "1",
                                        "app_accounts": "1", "play_enabled": "1"})
        firebase.save_key(self.portal.play.key_path, self.key)

    def settings(self, **values):
        self.portal.store.set_settings({k: str(v) for k, v in values.items()})

    def signed_in_app(self, email: str) -> App:
        a = App(self.port)
        a.enroll()
        test_app_api.TestAppApi.signup(self, a, email)
        return a

    def test_a_new_account_cannot_inherit_a_deleted_accounts_subscription(self):
        victim = self.signed_in_app("sub-owner@example.com")
        ref = victim.me()["play"]["account"]
        self.google.add_play_purchase("victim-play-token-0001-" + "v" * 30, PACKAGE, PRODUCT, ref, days=300)
        st, me = victim.call("POST", "/api/v1/play/verify", {"product_id": PRODUCT,
                                                            "purchase_token": "victim-play-token-0001-" + "v" * 30})
        self.assertEqual((st, me["plan"]), (200, "premium"))
        old_id = self.portal.store.user_by_email("sub-owner@example.com")["id"]
        self.assertEqual(victim.call("POST", "/api/v1/account/delete", {"password": PASSWORD})[0], 200)
        thief = self.signed_in_app("next-signup@example.com")  # the very next account
        self.assertGreater(self.portal.store.user_by_email("next-signup@example.com")["id"], old_id)
        self.assertNotEqual(thief.me()["play"]["account"], ref)
        st, data = thief.call("POST", "/api/v1/play/verify", {"product_id": PRODUCT,
                                                             "purchase_token": "victim-play-token-0001-" + "v" * 30})
        self.assertEqual((st, data["error"]), (403, "wrong_account"))
        self.assertEqual(thief.me()["plan"], "free")

    def test_password_reset_signs_out_app_devices(self):
        phone = self.signed_in_app("reset-me@example.com")
        self.assertIsNotNone(phone.me()["account"])
        # The sign-up code counts as a recent code: move it back past the one-minute resend throttle.
        self.portal.store._exec("UPDATE password_resets SET created_at = created_at - 120")
        st, _ = phone.call("POST", "/api/v1/forgot", {"login": "reset-me@example.com"})
        self.assertEqual(st, 200)
        mail = self.mails.wait("reset-me@example.com", 2)[-1]["text"]
        code = re.search(r"\b(\d{6})\b", mail).group(1)
        st, data = phone.call("POST", "/api/v1/forgot/verify", {"login": "reset-me@example.com", "code": code,
                                                               "password": "a brand new passphrase 9"})
        self.assertEqual(st, 200, data)
        self.assertIsNone(phone.me()["account"])  # whoever was signed in on a device is signed out

    def test_signup_does_the_same_hashing_work_for_existing_accounts(self):
        self.signed_in_app("taken@example.com")
        calls = []
        real = auth.hash_password

        def counting(pw):
            calls.append(1)
            return real(pw)

        probe = App(self.port)
        probe.enroll()
        with mock.patch.object(auth, "hash_password", counting):
            for email in ("brand-new@example.com", "taken@example.com"):
                calls.clear()
                st, _ = probe.call("POST", "/api/v1/signup", {"email": email, "password": "some long passphrase"})
                self.assertEqual(st, 200)
                if email.startswith("brand"):
                    new_work = len(calls)
        self.assertEqual(len(calls), new_work)  # no faster answer for an address that already has an account

    def test_account_deletion_works_with_app_sign_in_switched_off(self):
        phone = self.signed_in_app("leaves-later@example.com")
        self.settings(app_accounts=0)
        st, me = phone.call("POST", "/api/v1/account/delete", {"password": PASSWORD})
        self.assertEqual(st, 200, me)
        self.assertIsNone(self.portal.store.user_by_email("leaves-later@example.com"))

    def test_verifying_an_email_does_not_re_enable_a_disabled_account(self):
        probe = App(self.port)
        probe.enroll()
        self.assertEqual(probe.call("POST", "/api/v1/signup", {"email": "spam@example.com",
                                                               "password": "some long passphrase"})[0], 200)
        user = self.portal.store.user_by_email("spam@example.com")
        self.portal.store.update_user(user["id"], enabled=0)  # an administrator stops it before verification
        code = re.search(r"\b(\d{6})\b", self.mails.wait("spam@example.com", 1)[-1]["text"]).group(1)
        probe.call("POST", "/api/v1/signup/verify", {"email": "spam@example.com", "code": code})
        self.assertEqual(self.portal.store.user_by_email("spam@example.com")["enabled"], 0)


class TestAdMobCallbackParsing(unittest.TestCase):
    def setUp(self):
        self.key = ossl.generate("EC", "P-256")
        pem = ossl.public_to_pem(self.key).decode()
        self.verifier = rewards.AdMobVerifier(fetch=lambda: json.dumps({"keys": [{"keyId": 7, "pem": pem}]}).encode())

    def signed(self, custom_data: str) -> str:
        msg = urllib.parse.urlencode([("custom_data", custom_data), ("timestamp", str(int(time.time() * 1000))),
                                      ("transaction_id", "tx-1")])
        sig = base64.urlsafe_b64encode(ossl.sign_hashed(self.key, msg.encode(), "SHA256")).decode().rstrip("=")
        return f"{msg}&signature={sig}&key_id=7"

    def test_only_the_signed_part_counts(self):
        good = self.signed("nonce-of-my-own-ad")
        self.assertEqual(self.verifier.verify(good)["custom_data"], "nonce-of-my-own-ad")
        for extra in ("&custom_data=someone-elses-nonce", "&transaction_id=tx-2", "&key_id=8", "&signature=AAAA"):
            with self.assertRaises(rewards.SsvError):
                self.verifier.verify(good + extra)


class TestWindowsHardening(unittest.TestCase):
    def test_only_web_addresses_are_opened(self):
        try:
            from pqvpn import app  # the desktop window needs tkinter (not installed on servers)
        except ImportError as exc:
            self.skipTest(f"desktop app not importable here: {exc}")
        with mock.patch.object(app.subprocess, "Popen") as popen, mock.patch.object(app.webbrowser, "open") as wb:
            for bad in (r"C:\Windows\System32\calc.exe", "file:///C:/x.bat", "\\\\server\\share\\x.exe",
                        "javascript:alert(1)", 'https://ok.example/" C:\\x.exe', ""):
                app.open_url(bad)
            self.assertFalse(popen.called or wb.called)
            app.open_url("https://portal.example/pay/abc")
            self.assertTrue(popen.called or wb.called)

    @unittest.skipUnless(sys.platform == "win32", "the tray app is Windows-only")
    def test_shortcut_script_quotes_every_path(self):
        from pqvpn import winui
        ps = winui.shortcut_script("Desktop", r"C:\Users\O'Brien\python.exe", '-m pqvpn tray -c "C:\\a\'b\\c.toml"',
                                   r"C:\Users\O'Brien\icon.ico", "ShieldsVPN")
        self.assertIn(r"'C:\Users\O''Brien\python.exe'", ps)
        self.assertIn(r"'C:\Users\O''Brien\icon.ico,0'", ps)
        self.assertEqual(winui.ps_quote("a'b"), "'a''b'")


if __name__ == "__main__":
    unittest.main()
