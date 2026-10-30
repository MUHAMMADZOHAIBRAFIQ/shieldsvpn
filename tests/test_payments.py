"""Pro payments through Paddle: checkout links, verification against Paddle's API, webhooks, admin settings."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.portal import devices, payments  # noqa: E402
from tests.fake_paddle import FakePaddle, iso  # noqa: E402
from tests import test_app_api  # noqa: E402  (module import: unittest must not collect TestAppApi again)
from tests.test_app_api import App  # noqa: E402
from tests.test_portal import Browser  # noqa: E402

PRICE = "pri_01hv0vax6rv18t4tamj848ne4d"
PRODUCT = "pro_01hv0v8mbr0ejw5ve1p3f2rk6d"
CLIENT_TOKEN = "test_7d279f61a3499fed520f7cd8c08"
WEBHOOK_SECRET = "pdl_ntfset_test_secret_value"
PASSWORD = "purple mountain river 7"  # test_app_api.TestAppApi.signup's default


def signed(body: dict, secret: str = WEBHOOK_SECRET, ts: int | None = None) -> tuple[bytes, str]:
    raw = json.dumps(body).encode()
    ts = int(time.time()) if ts is None else ts
    h1 = hmac.new(secret.encode(), f"{ts}:".encode() + raw, hashlib.sha256).hexdigest()
    return raw, f"ts={ts};h1={h1}"


class TestPayments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_app_api.TestAppApi.setUpClass.__func__(cls)
        cls.paddle = FakePaddle()
        cls.portal.payments.client_factory = lambda s: payments.PaddleClient(
            s["paddle_env"], s["paddle_api_key"], base_url=cls.paddle.url)

    @classmethod
    def tearDownClass(cls):
        cls.paddle.stop()
        test_app_api.TestAppApi.tearDownClass.__func__(cls)

    def setUp(self):
        # Only the monthly plan is on sale, at a price the portal created earlier.
        self.paddle.refuse_intervals.clear()
        self.paddle.prices[PRICE] = {"id": PRICE, "status": "active", "product_id": PRODUCT,
                                     "billing_cycle": {"interval": "month", "frequency": 1},
                                     "unit_price": {"amount": "499", "currency_code": "USD"}}
        vault = self.portal.vault
        self.portal.store.set_settings({
            **devices.APP_DEFAULTS, **payments.DEFAULT_SETTINGS, "app_enrollment": "1", "app_accounts": "1",
            "portal_access": "admins", "payments_enabled": "1", "paddle_env": "sandbox", "paddle_product_id": PRODUCT,
            "pro_currency": "USD", "pro_price_month": "4.99", "paddle_price_month": PRICE,
            "paddle_price_history": PRICE, "paddle_client_token": CLIENT_TOKEN,
            "paddle_api_key": vault.seal("paddle_api_key", FakePaddle.API_KEY),
            "paddle_webhook_secret": vault.seal("paddle_webhook_secret", WEBHOOK_SECRET)})

    def settings(self, **values):
        self.portal.store.set_settings({k: str(v) for k, v in values.items()})

    def signed_in_app(self, email: str) -> App:
        app = App(self.port)
        app.enroll()
        test_app_api.TestAppApi.signup(self, app, email)
        return app

    def user(self, email: str) -> dict:
        return self.portal.store.user_by_email(email)

    def last_txn(self, email: str) -> dict:
        customer = self.user(email)["paddle_customer_id"]
        return [t for t in self.paddle.transactions.values() if t["customer_id"] == customer][-1]

    def admin(self) -> tuple[Browser, bytes]:
        """The first administrator, signed in, and the settings page."""
        admin = Browser(self.port)
        _, h, _ = admin.login("root", self.admin_pw)
        if h.get("Location") == "/account/password":
            _, _, page = admin.get("/account/password")
            new = "admin passphrase for payment tests"
            admin.post("/account/password", {"csrf": admin.csrf(page), "current": self.admin_pw, "new": new,
                                              "confirm": new})
            type(self).admin_pw = new
        _, _, page = admin.get("/admin/settings")
        return admin, page

    @staticmethod
    def payment_form(page: bytes, **fields) -> dict:
        """The Payments form as setUp left it (monthly 4.99 on sale), with ``fields`` changed."""
        return {"csrf": Browser.csrf(page), "payments_enabled": "on", "paddle_env": "sandbox",
                "paddle_product_id": PRODUCT, "pro_currency": "USD", "paddle_client_token": CLIENT_TOKEN,
                "pro_price_week": "", "pro_price_month": "4.99", "pro_price_year": "", "paddle_api_key": "",
                "paddle_webhook_secret": "", **fields}

    def price_settings(self) -> dict:
        s = self.portal.settings()
        return {k: v for k, v in s.items() if k.startswith(("pro_", "paddle_price_", "paddle_product"))}

    def test_checkout_needs_payments_on_and_an_account(self):
        app = App(self.port)
        app.enroll()
        st, data = app.call("POST", "/api/v1/checkout", {})
        self.assertEqual((st, data["error"]), (401, "sign_in_required"))
        self.portal.store.set_settings({"payments_enabled": "0"})
        me = app.me()
        self.assertEqual((me["features"]["payments"], me["price_label"], me["prices"]), (False, "", []))
        app = self.signed_in_app("nopay@example.com")
        st, data = app.call("POST", "/api/v1/checkout", {})
        self.assertEqual((st, data["error"]), (404, "disabled"))

    def test_paid_checkout_turns_on_pro_from_paddle_data_only(self):
        app = self.signed_in_app("buyer@example.com")
        me = app.me()
        self.assertEqual((me["features"]["payments"], me["price_label"]), (True, "USD 4.99 / month"))
        self.assertEqual(me["prices"], [{"period": "month", "name": "Monthly", "amount": "4.99", "currency": "USD",
                                         "label": "USD 4.99 / month"}])  # display data only: no Paddle ids
        st, data = app.call("POST", "/api/v1/checkout", {})
        self.assertEqual(st, 200, data)
        code = re.fullmatch(r"http://127\.0\.0\.1:8800/pay/([A-Za-z0-9_-]+)", data["url"]).group(1)
        user = self.user("buyer@example.com")
        txn = next(t for t in self.paddle.transactions.values() if t["customer_id"] == user["paddle_customer_id"])
        self.assertEqual(txn["custom_data"], {"shieldsvpn_user": str(user["id"])})  # set by the portal, not the buyer
        self.assertEqual(txn["items"][0]["price"]["id"], PRICE)

        b = Browser(self.port)
        st, h, page = b.get(f"/pay/{code}")
        self.assertEqual(st, 200)
        self.assertIn(f'data-txn="{txn["id"]}"'.encode(), page)
        self.assertIn(b'src="/static/pay.js"', page)
        self.assertIn("https://cdn.paddle.com", h["Content-Security-Policy"])
        self.assertIn("frame-src https://buy.paddle.com https://sandbox-buy.paddle.com", h["Content-Security-Policy"])
        self.assertNotIn("paddle", b.get("/login")[1]["Content-Security-Policy"])  # only the pay page is relaxed
        self.assertEqual(b.get("/pay/" + "x" * 30)[0], 404)

        self.assertEqual(app.me()["plan"], "free")  # not paid yet: nothing changes
        self.paddle.pay(txn["id"], days=30)
        me = app.me()  # back in the app: the portal asks Paddle
        self.assertEqual((me["plan"], me["can_connect"]), ("premium", True))
        self.assertAlmostEqual(me["pro_until"], time.time() + 31 * 86400, delta=60)
        self.assertEqual(self.portal.store.payments(self.user("buyer@example.com")["id"])[0]["status"], "completed")
        self.assertIn("plan_paid", [a["action"] for a in self.portal.store.recent_audit(10)])
        self.assertIn(b"Thank you", b.get(f"/pay/{code}/done")[2])
        st, data = app.call("POST", "/api/v1/checkout", {})
        self.assertEqual((st, data["error"]), (409, "already_pro"))
        st, data = app.call("POST", "/api/v1/manage", {})
        self.assertEqual(st, 200)
        self.assertTrue(data["url"].startswith("https://customer-portal.paddle.com/"))

    def test_unfinished_checkouts_are_capped(self):
        app = self.signed_in_app("eager@example.com")
        for _ in range(payments.MAX_OPEN_CHECKOUTS):
            self.assertEqual(app.call("POST", "/api/v1/checkout", {})[0], 200)
        st, data = app.call("POST", "/api/v1/checkout", {})
        self.assertEqual((st, data["error"]), (429, "rate_limited"))  # no flood of Paddle transactions
        customer = self.user("eager@example.com")["paddle_customer_id"]
        self.assertEqual(sum(t["customer_id"] == customer for t in self.paddle.transactions.values()),
                         payments.MAX_OPEN_CHECKOUTS)

    def test_foreign_or_wrong_price_transactions_are_ignored(self):
        app = self.signed_in_app("sneaky@example.com")
        _, data = app.call("POST", "/api/v1/checkout", {})
        txn = next(t for t in self.paddle.transactions.values()
                   if t["customer_id"] == self.user("sneaky@example.com")["paddle_customer_id"])
        txn["custom_data"] = {"shieldsvpn_user": "999999"}  # someone else's purchase
        self.paddle.pay(txn["id"])
        self.assertEqual(app.me()["plan"], "free")
        _, data = app.call("POST", "/api/v1/checkout", {})
        txn2 = [t for t in self.paddle.transactions.values() if t["id"] != txn["id"]
                and t["customer_id"] == txn["customer_id"]][-1]
        txn2["items"] = [{"price": {"id": "pri_01cheaperpricecheaperpri"}, "quantity": 1}]
        self.paddle.pay(txn2["id"])
        self.assertEqual(app.me()["plan"], "free")

    def test_webhook_signature_and_renewal(self):
        app = self.signed_in_app("renew@example.com")
        _, data = app.call("POST", "/api/v1/checkout", {})
        user = self.user("renew@example.com")
        txn = next(t for t in self.paddle.transactions.values() if t["customer_id"] == user["paddle_customer_id"])
        sid = self.paddle.pay(txn["id"], days=1)
        event = {"event_type": "subscription.activated", "data": {"id": sid, "status": "active",
                                                                   "custom_data": {"shieldsvpn_user": str(user["id"])}}}
        raw, sig = signed(event, secret="wrong")
        st, data = app.call("POST", "/api/v1/paddle/webhook", raw=raw, token=False,
                            headers={"Content-Type": "application/json", "Paddle-Signature": sig})
        self.assertEqual((st, data["error"]), (401, "bad_signature"))
        raw, sig = signed(event, ts=int(time.time()) - 3600)  # replayed from an hour ago
        st, _ = app.call("POST", "/api/v1/paddle/webhook", raw=raw, token=False,
                         headers={"Content-Type": "application/json", "Paddle-Signature": sig})
        self.assertEqual(st, 401)
        self.assertEqual(self.user("renew@example.com")["plan"], "free")
        raw, sig = signed(event)
        st, _ = app.call("POST", "/api/v1/paddle/webhook", raw=raw, token=False,
                         headers={"Content-Type": "application/json", "Paddle-Signature": sig})
        self.assertEqual(st, 200)
        first = self.user("renew@example.com")
        self.assertEqual(first["plan"], "premium")
        # Paddle renews: the periodic reconcile moves the end date to the new billing period.
        self.paddle.subscriptions[sid]["current_billing_period"]["ends_at"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() + 31 * 86400))
        self.assertGreaterEqual(self.portal.payments.reconcile_all(), 1)
        self.assertGreater(self.user("renew@example.com")["plan_expires"], first["plan_expires"] + 29 * 86400)

    def test_cancelled_before_the_first_check_ends_after_the_grace_day(self):
        """A subscription the portal first sees already cancelled gets the grace day, never an open-ended Pro."""
        for email, cancelled_ago, plan in (("quit-early@example.com", 2 * 86400, "free"),
                                           ("quit-now@example.com", 0, "premium")):
            app = self.signed_in_app(email)
            app.call("POST", "/api/v1/checkout", {})
            user = self.user(email)
            txn = next(t for t in self.paddle.transactions.values() if t["customer_id"] == user["paddle_customer_id"])
            sid = self.paddle.pay(txn["id"], status="canceled")
            cancelled_at = int(time.time()) - cancelled_ago
            self.paddle.subscriptions[sid]["canceled_at"] = iso(cancelled_at)
            me = app.me()  # the portal's first look at this purchase
            self.assertEqual(me["plan"], plan, email)
            self.assertEqual(self.user(email)["plan_expires"], cancelled_at + payments.GRACE, email)

    def test_admin_sets_weekly_monthly_and_yearly_prices(self):
        admin, page = self.admin()
        for period in ("week", "month", "year"):
            self.assertIn(f'name="pro_price_{period}"'.encode(), page)
        early = self.signed_in_app("early-bird@example.com")
        self.assertEqual(early.call("POST", "/api/v1/checkout", {})[0], 200)  # no choice sent: the monthly plan
        early_txn = self.last_txn("early-bird@example.com")
        self.assertEqual(early_txn["items"][0]["price"]["id"], PRICE)

        st, _, body = admin.post("/admin/settings/payments",
                                 self.payment_form(page, pro_price_week="1.99", pro_price_year="39.9"))
        self.assertIn(b"Created 2 new price(s) at Paddle", body)
        s = self.portal.settings()
        self.assertEqual((s["paddle_price_month"], s["pro_price_year"]), (PRICE, "39.90"))  # same amount: same price
        made = {p: self.paddle.prices[s[f"paddle_price_{p}"]] for p in ("week", "year")}
        self.assertEqual({p: (m["billing_cycle"], m["unit_price"], m["product_id"]) for p, m in made.items()}, {
            "week": ({"interval": "week", "frequency": 1}, {"amount": "199", "currency_code": "USD"}, PRODUCT),
            "year": ({"interval": "year", "frequency": 1}, {"amount": "3990", "currency_code": "USD"}, PRODUCT)})

        app = self.signed_in_app("chooser@example.com")
        me = app.me()
        self.assertEqual([(p["period"], p["label"]) for p in me["prices"]],
                         [("week", "USD 1.99 / week"), ("month", "USD 4.99 / month"), ("year", "USD 39.90 / year")])
        self.assertEqual(me["price_label"], "USD 4.99 / month")  # for app builds that show one price
        st, data = app.call("POST", "/api/v1/checkout", {"period": "year"})
        self.assertEqual(st, 200, data)
        self.assertEqual(self.last_txn("chooser@example.com")["items"][0]["price"]["id"], s["paddle_price_year"])
        st, data = app.call("POST", "/api/v1/checkout", {"period": "day"})
        self.assertEqual((st, data["error"]), (400, "bad_period"))

        # A new monthly amount gets a new price; the old one is archived at Paddle (its subscribers keep it), and a
        # checkout started on it before the change still turns Pro on once paid.  Clearing weekly stops selling it.
        _, _, page = admin.get("/admin/settings")
        st, _, body = admin.post("/admin/settings/payments",
                                 self.payment_form(page, pro_price_month="5.99", pro_price_year="39.90"))
        self.assertIn(b"Created 1 new price(s) at Paddle", body)
        s2 = self.portal.settings()
        self.assertNotEqual(s2["paddle_price_month"], PRICE)
        self.assertEqual(s2["paddle_price_year"], s["paddle_price_year"])
        self.assertEqual((s2["paddle_price_week"], s2["pro_price_week"]), ("", ""))
        self.assertEqual(self.paddle.prices[PRICE]["status"], "archived")
        self.assertEqual(self.paddle.prices[s["paddle_price_week"]]["status"], "archived")
        self.assertEqual(self.paddle.prices[s2["paddle_price_month"]]["unit_price"]["amount"], "599")
        self.assertEqual([p["period"] for p in app.me()["prices"]], ["month", "year"])
        self.assertEqual(app.call("POST", "/api/v1/checkout", {"period": "week"})[1]["error"], "bad_period")
        self.paddle.pay(early_txn["id"])
        self.assertEqual(early.me()["plan"], "premium")

    def test_a_price_paddle_refuses_saves_nothing(self):
        admin, page = self.admin()
        before, existing = self.price_settings(), set(self.paddle.prices)
        self.paddle.refuse_intervals.add("year")
        st, _, body = admin.post("/admin/settings/payments",
                                 self.payment_form(page, pro_price_week="1.99", pro_price_year="39.99"))
        self.assertIn(b"Nothing was saved", body)
        self.assertIn(b"year refused by the test", body)
        self.assertEqual(self.price_settings(), before)
        created = [self.paddle.prices[p] for p in set(self.paddle.prices) - existing]
        self.assertEqual([(p["billing_cycle"]["interval"], p["status"]) for p in created], [("week", "archived")])

    def test_admin_price_validation(self):
        admin, page = self.admin()
        before = self.price_settings()
        for fields, message in (
                ({"pro_price_week": "4,99"}, b"Weekly price: enter an amount like 4.99"),
                ({"pro_price_week": "0"}, b"Weekly price: must be more than 0"),
                ({"pro_price_year": "4.999"}, b"Yearly price: enter an amount like 4.99"),
                ({"pro_currency": "JPY", "pro_price_month": "500.5"}, b"Monthly price: JPY has no decimal places"),
                ({"pro_currency": "XYZ"}, b"Choose a currency"),
                ({"paddle_product_id": "prod-1"}, b"product ID looks like pro_01h"),
                ({"paddle_product_id": "", "pro_price_week": "1.99"}, b"enter the Paddle product ID")):
            st, _, body = admin.post("/admin/settings/payments", self.payment_form(page, **fields))
            self.assertIn(message, body, fields)
        self.assertEqual(self.price_settings(), before)

    def test_web_upgrade_page_offers_each_plan(self):
        year = "pri_01hv0vbyearyearyearyearyea"
        self.paddle.prices[year] = {"id": year, "status": "active", "product_id": PRODUCT}
        self.settings(portal_access="everyone", pro_price_year="39.90", paddle_price_year=year)
        self.signed_in_app("web-buyer@example.com")
        b = Browser(self.port)
        st, h, _ = b.login("web-buyer@example.com", PASSWORD)
        self.assertEqual((st, h["Location"]), (303, "/"))
        _, _, page = b.get("/upgrade")
        self.assertIn(b'name="period" value="month" checked', page)
        self.assertIn(b"USD 39.90 / year", page)
        self.assertNotIn(year.encode(), page)
        st, h, _ = b.post("/upgrade/checkout", {"csrf": Browser.csrf(page), "period": "year"})
        self.assertEqual(st, 303)
        self.assertTrue(h["Location"].startswith("/pay/"))
        self.assertEqual(self.last_txn("web-buyer@example.com")["items"][0]["price"]["id"], year)

    def test_admin_payment_settings_keep_secrets_sealed(self):
        admin, page = self.admin()
        self.assertIn(b'id="payments"', page)
        self.assertNotIn(FakePaddle.API_KEY.encode(), page)  # never echoed back
        st, _, body = admin.post("/admin/settings/payments",
                                 self.payment_form(page, paddle_api_key="pdl_new_key_value_123"))
        self.assertIn(b"Payment settings saved", body)
        self.assertNotIn(b"new price(s)", body)  # nothing about the prices changed: no price created at Paddle
        raw = self.portal.store.settings()["paddle_api_key"]
        self.assertTrue(raw.startswith("enc:v1:"))  # sealed at rest
        self.assertEqual(self.portal.settings()["paddle_api_key"], "pdl_new_key_value_123")

    def test_units(self):
        self.assertEqual(payments.iso_to_epoch("2026-11-22T10:00:00.123456Z"), 1795341600)
        with self.assertRaises(ValueError):
            payments.iso_to_epoch("tomorrow")
        raw, sig = signed({"a": 1})
        self.assertTrue(payments.verify_signature(raw, sig, WEBHOOK_SECRET, time.time()))
        self.assertFalse(payments.verify_signature(raw + b" ", sig, WEBHOOK_SECRET, time.time()))
        self.assertFalse(payments.verify_signature(raw, "garbage", WEBHOOK_SECRET, time.time()))
        self.assertFalse(payments.ready({"payments_enabled": "1"}))
        self.assertEqual((payments.normalize_amount(" 4.9 ", "USD"), payments.normalize_amount("", "USD")), ("4.90", ""))
        self.assertEqual((payments.to_minor("39.90", "USD"), payments.to_minor("500", "JPY")), ("3990", "500"))
        for bad in ("0", "-1", "1e3", "4.999", "1,5", "NaN"):
            with self.assertRaises(ValueError):
                payments.normalize_amount(bad, "USD")
        s = {"pro_currency": "EUR", "pro_price_year": "40.00", "paddle_price_year": PRICE, "pro_price_week": "1.00"}
        self.assertEqual(payments.offers(s), [{"period": "year", "name": "Yearly", "amount": "40.00", "currency": "EUR",
                                               "label": "EUR 40.00 / year"}])  # weekly has no Paddle price yet
        self.assertEqual(payments.default_period(s), "year")
        self.assertEqual(payments.known_prices({"paddle_price_id": PRICE, "paddle_price_history": ",x,"}), {PRICE})
        with self.assertRaises(payments.PaymentError):
            payments.PaddleClient("sandbox", "k").transaction("../../customers")  # ids are validated before use


if __name__ == "__main__":
    unittest.main()
