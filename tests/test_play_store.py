"""Google Play requirements on the server side: Pro bought through Google Play Billing (checked with Google's API)
and account deletion from the app."""

from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.portal import auth, devices, firebase, play  # noqa: E402
from tests import test_app_api  # noqa: E402  (module import: unittest must not collect TestAppApi again)
from tests.fake_firestore import FakeGoogle, make_key  # noqa: E402
from tests.test_app_api import App  # noqa: E402
from tests.test_portal import Browser  # noqa: E402

PACKAGE, PRODUCT = "com.shieldsvpn.vpn", "shieldsvpn_pro"


def token(n: int) -> str:
    return f"opaque-play-token.{n:04d}.AO-J1Oz" + "x" * 40


class TestPlayStore(unittest.TestCase):
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
        app = App(self.port)
        app.enroll()
        test_app_api.TestAppApi.signup(self, app, email)
        return app

    def user(self, email: str) -> dict:
        return self.portal.store.user_by_email(email)

    def verify(self, app: App, tok: str, product: str = PRODUCT):
        return app.call("POST", "/api/v1/play/verify", {"product_id": product, "purchase_token": tok})

    # ---------------------------------------------------------------- Google Play Billing
    def test_play_billing_is_off_until_configured(self):
        self.portal.store.set_settings({"play_enabled": "0"})
        app = self.signed_in_app("play-off@example.com")
        me = app.me()
        self.assertEqual((me["features"]["play"], me["play"]), (False, None))
        st, data = self.verify(app, token(1))
        self.assertEqual((st, data["error"]), (404, "disabled"))
        self.portal.store.set_settings({"play_enabled": "1"})
        os.remove(self.portal.play.key_path)
        self.assertFalse(self.portal.play.ready())  # switched on but no key: still off

    def test_signed_in_purchase_turns_on_pro(self):
        anon = App(self.port)
        anon.enroll()
        me = anon.me()
        self.assertEqual((me["features"]["play"], me["play"]), (True, None))  # no account: no account reference
        self.assertEqual(self.verify(anon, token(2))[1]["error"], "sign_in_required")

        app = self.signed_in_app("play-buyer@example.com")
        me = app.me()
        ref = me["play"]["account"]
        self.assertEqual((me["play"]["product"], len(ref)), (PRODUCT, 32))
        uid = self.user("play-buyer@example.com")["id"]
        self.assertEqual(ref, play.account_ref(self.portal.vault.subkey("play-account"), uid))  # keyed HMAC
        self.assertNotEqual(ref, play.account_ref(b"another portal's secret", uid))
        self.google.add_play_purchase(token(2), PACKAGE, PRODUCT, ref, days=30, base_plan="monthly")
        st, me = self.verify(app, token(2))
        self.assertEqual(st, 200, me)
        self.assertEqual((me["plan"], me["can_connect"]), ("premium", True))
        self.assertAlmostEqual(me["pro_until"], time.time() + 31 * 86400, delta=120)
        self.assertEqual(self.google.play_acks, [token(2)])  # acknowledged by the portal, once
        self.assertEqual(self.verify(app, token(2))[0], 200)  # the app re-sends it on every start (restore)
        self.assertEqual(self.google.play_acks, [token(2)])
        self.assertIn("plan_paid", [a["action"] for a in self.portal.store.recent_audit(10)])
        self.assertNotIn(token(2), str(self.portal.store.recent_audit(20)))  # tokens are never logged

        other = self.signed_in_app("play-thief@example.com")
        self.assertEqual(self.verify(other, token(2))[1]["error"], "token_in_use")
        self.google.add_play_purchase(token(3), PACKAGE, PRODUCT, ref)  # bought for play-buyer's account
        self.assertEqual(self.verify(other, token(3))[1]["error"], "wrong_account")
        self.assertEqual(other.me()["plan"], "free")
        self.google.add_play_purchase(token(4), PACKAGE, "some_other_product", other.me()["play"]["account"])
        self.assertEqual(self.verify(other, token(4), "some_other_product")[1]["error"], "bad_product")
        self.assertEqual(self.verify(other, token(4))[1]["error"], "bad_product")
        self.assertEqual(self.verify(other, "short")[1]["error"], "bad_token")
        self.assertEqual(self.verify(other, token(99))[1]["error"], "google")  # Google does not know it

    def test_unpaid_states_grant_nothing_and_renewals_extend(self):
        app = self.signed_in_app("play-states@example.com")
        ref = app.me()["play"]["account"]
        for n, state in ((10, "SUBSCRIPTION_STATE_PENDING"), (11, "SUBSCRIPTION_STATE_ON_HOLD"),
                         (12, "SUBSCRIPTION_STATE_EXPIRED")):
            self.google.add_play_purchase(token(n), PACKAGE, PRODUCT, ref, state=state)
            st, me = self.verify(app, token(n))
            self.assertEqual((st, me["plan"]), (200, "free"), state)
        self.assertEqual(self.google.play_acks.count(token(10)), 0)  # pending purchases are not acknowledged

        # A weekly test purchase two days before its renewal (the reconcile looks at the last three days).
        self.google.add_play_purchase(token(13), PACKAGE, PRODUCT, ref, days=2, base_plan="weekly", test=True)
        self.assertEqual(self.verify(app, token(13))[1]["plan"], "premium")
        first = self.user("play-states@example.com")["plan_expires"]
        # Renewal: Google moves the expiry; the periodic reconcile picks it up.
        self.google.play_subs[token(13)][1]["lineItems"][0]["expiryTime"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + 9 * 86400))
        self.assertGreaterEqual(self.portal.play.reconcile_all(), 1)
        self.assertGreater(self.user("play-states@example.com")["plan_expires"], first + 6 * 86400)
        # Canceled = auto-renew off, still paid until the expiry: Pro stays, and is never shortened.
        before = self.user("play-states@example.com")["plan_expires"]
        self.google.play_subs[token(13)][1]["subscriptionState"] = "SUBSCRIPTION_STATE_CANCELED"
        self.assertEqual(self.verify(app, token(13))[1]["plan"], "premium")
        self.assertEqual(self.user("play-states@example.com")["plan_expires"], before)
        # A plan change at Google issues a new token linked to the old one: the old one is no longer re-checked.
        self.google.add_play_purchase(token(14), PACKAGE, PRODUCT, ref, days=365, base_plan="yearly",
                                      linked=token(13))
        self.verify(app, token(14))
        self.assertEqual(self.portal.store.play_purchase(token(13))["replaced"], 1)
        self.assertNotIn(token(13), [r["token"] for r in self.portal.store.play_purchases_due(time.time() + 1e9)])

    def test_admin_play_settings(self):
        admin = Browser(self.port)
        _, h, _ = admin.login("root", self.admin_pw)
        if h.get("Location") == "/account/password":
            _, _, page = admin.get("/account/password")
            new = "admin passphrase for play tests"
            admin.post("/account/password", {"csrf": admin.csrf(page), "current": self.admin_pw, "new": new,
                                              "confirm": new})
            type(self).admin_pw = new
        _, _, page = admin.get("/admin/settings")
        self.assertIn(b'id="play"', page)
        self.assertNotIn(self.key["private_key"][40:80].encode(), page)  # the key is never shown
        form = {"csrf": admin.csrf(page), "play_enabled": "on", "play_package": "not a package",
                "play_product_id": PRODUCT, "key_json": ""}
        self.assertIn(b"package name looks like", admin.post("/admin/settings/play", form)[2])
        untrusted, _ = make_key()  # Google does not know this key
        os.remove(self.portal.play.key_path)
        body = admin.post("/admin/settings/play", {**form, "play_package": PACKAGE,
                                                   "key_json": firebase.json.dumps(untrusted)})[2]
        self.assertIn(b"Google rejected the key", body)
        self.assertFalse(os.path.exists(self.portal.play.key_path))  # a rejected key is not kept
        body = admin.post("/admin/settings/play", {**form, "play_package": PACKAGE,
                                                   "key_json": firebase.json.dumps(self.key)})[2]
        self.assertIn(b"Google Play settings saved", body)
        self.assertTrue(self.portal.play.ready())

    # ---------------------------------------------------------------- account deletion
    def test_account_deletion_from_the_app(self):
        app = self.signed_in_app("leaver@example.com")
        uid = self.user("leaver@example.com")["id"]
        st, data = app.call("POST", "/api/v1/account/delete", {"password": "wrong password here"})
        self.assertEqual((st, data["error"]), (401, "invalid"))
        self.assertEqual(self.portal.store.vpn_device_by_token(app.token)["failed_logins"], 1)  # counted
        secret = auth.new_totp_secret()
        self.portal.store.update_user(uid, totp_secret=secret, totp_enabled=1)
        st, data = app.call("POST", "/api/v1/account/delete", {"password": test_app_api_password()})
        self.assertEqual((st, data["error"]), (401, "totp_required"))
        st, me = app.call("POST", "/api/v1/account/delete", {"password": test_app_api_password(),
                                                            "code": auth.hotp(secret, auth.totp_step())})
        self.assertEqual(st, 200, me)
        self.assertIsNone(self.portal.store.user(uid))
        self.assertEqual((me["account"], me["plan"], me["can_connect"]), (None, "free", False))
        self.assertIn("account_deleted", [a["action"] for a in self.portal.store.recent_audit(10)])
        st, data = app.call("POST", "/api/v1/login", {"login": "leaver@example.com",
                                                      "password": test_app_api_password()})
        self.assertEqual(st, 401)  # the account is gone

        anon = App(self.port)
        anon.enroll()
        self.assertEqual(anon.call("POST", "/api/v1/account/delete", {"password": "x"})[1]["error"],
                         "sign_in_required")

    def test_administrators_cannot_delete_themselves_from_an_app(self):
        root = self.portal.store.user_by_name("root")
        app = App(self.port)
        app.enroll()
        self.portal.store.update_vpn_device(self.portal.store.vpn_device_by_token(app.token)["id"],
                                            user_id=root["id"], known_user_id=root["id"])
        st, data = app.call("POST", "/api/v1/account/delete", {"password": self.admin_pw})
        self.assertEqual((st, data["error"]), (403, "admin"))
        self.assertIsNotNone(self.portal.store.user_by_name("root"))


def test_app_api_password() -> str:
    return test_app_api.TestAppApi.signup.__defaults__[0]


if __name__ == "__main__":
    unittest.main()
