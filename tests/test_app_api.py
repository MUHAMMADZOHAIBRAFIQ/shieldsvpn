"""App API tests: device enrollment, Free time from ads (AdMob SSV), app sign-in, and VPN enforcement."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import pki  # noqa: E402
from pqvpn.config import load_portal  # noqa: E402
from pqvpn.crypto import ossl  # noqa: E402
from pqvpn.crypto.suites import DEFAULT_CA_SIG_ALGS, DEFAULT_PEER_SIG_ALGS, sig_alg_by_name  # noqa: E402
from pqvpn.portal import auth, devices, rewards  # noqa: E402
from pqvpn.portal.access import PortalAccess  # noqa: E402
from pqvpn.portal.service import portal_init  # noqa: E402
from pqvpn.portal.web import Portal  # noqa: E402
from pqvpn.protocol import RateLimiter  # noqa: E402
from pqvpn.runner import crypto_cfg, icmp_echo, loopback_pair, server_cfg  # noqa: E402
from tests.test_portal import Browser, MailCapture  # noqa: E402

auth.SCRYPT_N = 1 << 14  # faster hashing in tests (the cost is stored in each hash)
ML_DSA_65 = sig_alg_by_name("ML-DSA-65")


class App:
    """What the Android/Windows app does over HTTP."""

    def __init__(self, port: int):
        self.port, self.token, self.key, self.profile = port, None, None, None

    def call(self, method: str, path: str, body=None, headers=None, raw: bytes | None = None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"Host": f"127.0.0.1:{self.port}"}
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if token and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        out = r.read()
        conn.close()
        return r.status, (json.loads(out) if out and r.headers.get("Content-Type") == "application/json" else out)

    def enroll(self, platform: str = "android"):
        self.key = ML_DSA_65.generate()
        st, data = self.call("POST", "/api/v1/enroll", {
            "platform": platform, "key_alg": "ML-DSA-65",
            "public_key": base64.b64encode(ML_DSA_65.public_bytes(self.key)).decode()})
        if st == 200:
            self.token, self.profile = data["token"], data["profile"]
        return st, data

    def me(self) -> dict:
        st, data = self.call("GET", "/api/v1/me")
        assert st == 200, (st, data)
        return data


class TestAppApi(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqvpn-appapi-")
        cls.admin_pw = portal_init(cls.tmp, server_name="vpn.test", endpoint="127.0.0.1:51820",
                                   subnet="10.98.0.0/24", admin="root", listen=["127.0.0.1:8800"],
                                   public_url="http://127.0.0.1:8800/", issuer="Test VPN", psk=True, nat="",
                                   ca_alg="SLH-DSA-SHA2-128s")
        cfg = load_portal(os.path.join(cls.tmp, "portal.toml"))
        cfg.listen = [("127.0.0.1", 0)]
        cfg.require_2fa_for_admins = False
        cls.portal = Portal(cfg)
        cls.portal.limiter = RateLimiter(rate=1000, burst=1000)
        cls.mails = MailCapture()
        cls.portal.mailer = cls.mails
        cls.portal.store.set_settings({"smtp_user": "vpn@example.com", "smtp_password": "app-password"})
        # A stand-in for Google's AdMob verifier key server, serving our own P-256 key.
        cls.ec_key = ossl.generate("EC", "P-256")
        pem = ossl.public_to_pem(cls.ec_key).decode()
        cls.portal.admob = rewards.AdMobVerifier(fetch=lambda: json.dumps(
            {"keys": [{"keyId": 3335741209, "pem": pem, "base64": ""}]}).encode())
        cls.port = int(cls.portal.start()[0].rsplit(":", 1)[1].strip("/"))

    @classmethod
    def tearDownClass(cls):
        cls.portal.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.portal.store.set_settings({**devices.APP_DEFAULTS, "app_enrollment": "1"})

    def settings(self, **values):
        self.portal.store.set_settings({k: str(v) for k, v in values.items()})

    def ssv_query(self, nonce: str, tx: str, ts_ms: int | None = None, tamper: bool = False) -> str:
        ts_ms = int(time.time() * 1000) if ts_ms is None else ts_ms
        msg = urllib.parse.urlencode([
            ("ad_network", "5450213213286189855"), ("ad_unit", "1234567890"), ("custom_data", nonce),
            ("reward_amount", "30"), ("reward_item", "minutes"), ("timestamp", str(ts_ms)),
            ("transaction_id", tx), ("user_id", "")])
        sig = ossl.sign_hashed(self.ec_key, msg.encode(), "SHA256")
        signed = msg.replace("reward_amount=30", "reward_amount=999") if tamper else msg
        return signed + "&signature=" + base64.urlsafe_b64encode(sig).decode().rstrip("=") + "&key_id=3335741209"

    def signup(self, app: App, email: str, password: str = "purple mountain river 7") -> dict:
        self.settings(app_accounts=1)
        st, data = app.call("POST", "/api/v1/signup", {"email": email, "password": password})
        self.assertEqual(st, 200, data)
        code = re.search(r"\b(\d{6})\b", self.mails.wait(email, 1)[-1]["text"]).group(1)
        st, data = app.call("POST", "/api/v1/signup/verify", {"email": email, "code": code})
        self.assertEqual(st, 200, data)
        return data

    # ---------------------------------------------------------------- enrollment
    def test_enrollment_is_off_by_default_and_issues_a_device_certificate(self):
        self.settings(app_enrollment=0)
        st, data = App(self.port).enroll()
        self.assertEqual((st, data["error"]), (404, "disabled"))
        self.settings(app_enrollment=1)
        app = App(self.port)
        st, data = app.enroll()
        self.assertEqual(st, 200, data)
        prof = data["profile"]
        self.assertTrue(devices.is_device_subject(prof["subject"]))
        self.assertNotIn("private", json.dumps(data).lower())  # the portal never sees or returns a private key
        cert = pki.Certificate.from_pem(prof["certificate"])
        self.assertEqual(cert.subject, prof["subject"])
        self.assertEqual(cert.addresses, (prof["address"] + "/32",))
        pki.Identity(cert, app.key)  # the certificate is for the app's own key
        trust = pki.TrustStore.load([self.portal.cfg.ca_certificate], peer_algs=DEFAULT_PEER_SIG_ALGS,
                                    ca_algs=DEFAULT_CA_SIG_ALGS + ("SLH-DSA-SHA2-128s",))
        trust.verify(cert, pki.ROLE_CLIENT)
        self.assertEqual(prof["psk"], "")  # anyone can register, so a PSK given here would be public
        self.assertEqual((prof["server"], prof["server_name"]), ("127.0.0.1:51820", "vpn.test"))
        me = data["me"]
        self.assertEqual((me["plan"], me["can_connect"], me["account"]), ("free", False, None))
        # Two devices never share an address, and devices never take a user's address.
        other = App(self.port)
        other.enroll()
        users_ips = {u["vpn_ip"] for u in self.portal.store.users() if u["vpn_ip"]}
        self.assertNotEqual(other.profile["address"], prof["address"])
        self.assertFalse({other.profile["address"], prof["address"]} & users_ips)
        audit = [a["action"] for a in self.portal.store.recent_audit(5)]
        self.assertIn("device_enrolled", audit)

    def test_enrollment_rejects_bad_keys_and_is_capped_per_network(self):
        app = App(self.port)
        st, data = app.call("POST", "/api/v1/enroll", {"platform": "android", "key_alg": "ML-DSA-87",
                                                        "public_key": "AAAA"})
        self.assertEqual((st, data["error"]), (400, "bad_key"))
        st, data = app.call("POST", "/api/v1/enroll", {"platform": "android", "key_alg": "ML-DSA-65",
                                                        "public_key": base64.b64encode(b"x" * 100).decode()})
        self.assertEqual((st, data["error"]), (400, "bad_key"))
        st, data = app.call("POST", "/api/v1/enroll", {"platform": "toaster", "key_alg": "ML-DSA-65",
                                                        "public_key": "AAAA"})
        self.assertEqual(st, 400)
        already = self.portal.store.enrollments_since("127.0.0.1", int(time.time()) - 86400)
        self.settings(enroll_per_ip_day=already + 1)
        self.assertEqual(App(self.port).enroll()[0], 200)
        st, data = App(self.port).enroll()
        self.assertEqual((st, data["error"]), (429, "rate_limited"))

    def due_for_renewal(self, subject: str) -> None:
        """Pretend the device's certificate expires in a week (renewal is refused before it is due)."""
        self.portal.store._exec("UPDATE vpn_devices SET cert_expires = ? WHERE subject = ?",
                                (int(time.time()) + 7 * 86400, subject))

    def test_renew_supersedes_the_old_certificate(self):
        app = App(self.port)
        app.enroll()
        old = pki.Certificate.from_pem(app.profile["certificate"])
        app.key = ML_DSA_65.generate()
        body = {"key_alg": "ML-DSA-65", "public_key": base64.b64encode(ML_DSA_65.public_bytes(app.key)).decode()}
        st, data = app.call("POST", "/api/v1/renew", body)
        self.assertEqual((st, data["error"]), (409, "not_due"))  # each issuance costs a CA signature
        self.due_for_renewal(old.subject)
        st, data = app.call("POST", "/api/v1/renew", body)
        self.assertEqual(st, 200, data)
        new = pki.Certificate.from_pem(data["profile"]["certificate"])
        self.assertEqual((new.subject, new.addresses), (old.subject, old.addresses))
        device = self.portal.store.vpn_device_by_subject(old.subject)
        self.assertEqual(device["active_serial"], new.serial_hex)

    # ---------------------------------------------------------------- API hygiene
    def test_api_requires_a_device_token_and_ignores_portal_cookies(self):
        app = App(self.port)
        st, data = app.call("GET", "/api/v1/me")
        self.assertEqual((st, data["error"]), (401, "unauthorized"))
        st, _ = app.call("GET", "/api/v1/me", headers={"Authorization": "Bearer " + "x" * 43})
        self.assertEqual(st, 401)
        admin = Browser(self.port)
        admin.login("root", self.admin_pw)
        st, _ = app.call("GET", "/api/v1/me", headers={"Cookie": "; ".join(f"{k}={v}" for k, v in admin.cookies.items())})
        self.assertEqual(st, 401)  # a browser session grants nothing here
        app.enroll()
        st, data = app.call("POST", "/api/v1/logout", {}, headers={"Origin": "https://evil.example"})
        self.assertEqual((st, data["error"]), (403, "cross_site"))
        st, data = app.call("POST", "/api/v1/logout", raw=b"a=b",
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(st, 415)
        st, data = app.call("POST", "/api/v1/logout", raw=b"[1]", headers={"Content-Type": "application/json"})
        self.assertEqual(st, 400)
        st, _ = app.call("GET", "/api/v1/nothing")
        self.assertEqual(st, 404)
        st, _ = app.call("GET", "/api/v1/me", headers={"Host": "evil.example"})
        self.assertEqual(st, 421)  # DNS-rebinding guard still runs first

    def test_each_device_is_rate_limited(self):
        app = App(self.port)
        app.enroll()
        saved = self.portal.device_limiter
        self.portal.device_limiter = RateLimiter(rate=0.001, burst=3)
        try:
            for _ in range(3):
                self.assertEqual(app.call("GET", "/api/v1/me")[0], 200)
            st, data = app.call("GET", "/api/v1/me")
            self.assertEqual((st, data["error"]), (429, "rate_limited"))
            other = App(self.port)  # another device has its own budget
            other.enroll()
            self.assertEqual(other.call("GET", "/api/v1/me")[0], 200)
        finally:
            self.portal.device_limiter = saved

    def test_plain_http_is_refused_when_the_portal_is_published_by_name(self):
        cfg = load_portal(os.path.join(self.tmp, "portal.toml"))
        cfg.listen = [("127.0.0.1", 0)]
        for url, refused in (("http://vpn.example.com/", True), ("https://abc.ply.gg:1234/", True),
                             ("http://1.1.1.1/", True), ("http://10.0.2.2:8899/", False),
                             ("http://127.0.0.1:8800/", False), ("", False)):
            cfg.public_url = url
            portal = Portal(cfg)
            if refused:
                with self.assertRaises(SystemExit, msg=url):
                    portal.start()
            else:
                portal.start()
                portal.stop()
        cfg.public_url, cfg.allow_insecure_http = "http://vpn.example.com/", True  # explicit opt-out still works
        portal = Portal(cfg)
        portal.start()
        portal.stop()

    # ---------------------------------------------------------------- free time from ads
    def test_admob_test_mode_grants_time_once_and_respects_the_daily_limit(self):
        app = App(self.port)
        app.enroll()
        st, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        self.assertEqual((st, data["error"]), (404, "disabled"))
        self.settings(admob_enabled=1, free_minutes=30, free_daily_rewards=2)
        st, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        self.assertEqual(st, 200, data)
        nonce = data["nonce"]
        st, data = app.call("POST", "/api/v1/reward/claim", {"nonce": nonce})
        self.assertEqual((st, data["error"]), (403, "verification_required"))  # SSV is required by default
        self.settings(admob_require_ssv=0)
        before = time.time()
        st, me = app.call("POST", "/api/v1/reward/claim", {"nonce": nonce})
        self.assertEqual(st, 200, me)
        self.assertTrue(me["can_connect"])
        self.assertEqual((me["free_seconds"], me["free_counting"]), (1800, False))  # a balance, not running
        self.assertAlmostEqual(me["free_until"], before + 1800, delta=5)  # what older app builds read
        st, _ = app.call("POST", "/api/v1/reward/claim", {"nonce": nonce})
        self.assertEqual(st, 409)  # single use
        _, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        st, me = app.call("POST", "/api/v1/reward/claim", {"nonce": data["nonce"]})
        self.assertEqual(me["free_seconds"], 3600)  # time adds up
        self.assertEqual(me["rewards_left_today"], 0)
        st, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        self.assertEqual((st, data["error"]), (429, "daily_limit"))
        other = App(self.port)
        other.enroll()
        st, data = other.call("POST", "/api/v1/reward/claim", {"nonce": nonce})
        self.assertEqual(st, 400)  # another device's nonce is useless

    def test_admob_server_side_verification(self):
        self.settings(admob_enabled=1)
        app = App(self.port)
        app.enroll()
        _, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        nonce = data["nonce"]
        for bad in (self.ssv_query(nonce, "tx-1", tamper=True),
                    self.ssv_query(nonce, "tx-1", ts_ms=int((time.time() - 7200) * 1000)),
                    self.ssv_query(nonce, "tx-1").replace("key_id=3335741209", "key_id=1")):
            st, data = app.call("GET", "/api/v1/admob/ssv?" + bad, token=False)
            self.assertEqual(st, 400, bad)
        self.assertFalse(app.me()["can_connect"])
        st, data = app.call("GET", "/api/v1/admob/ssv?" + self.ssv_query(nonce, "tx-1"), token=False)
        self.assertEqual((st, data), (200, {"ok": True}))
        self.assertTrue(app.me()["can_connect"])
        st, data = app.call("GET", "/api/v1/admob/ssv?" + self.ssv_query(nonce, "tx-1"), token=False)
        self.assertEqual((st, data), (200, {"ok": False}))  # Google retrying the same callback grants nothing
        _, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        st, data = app.call("GET", "/api/v1/admob/ssv?" + self.ssv_query(data["nonce"], "tx-1"), token=False)
        self.assertEqual(data, {"ok": False})  # a reused transaction id cannot be attached to a new nonce
        self.assertIn("reward_rejected", [a["action"] for a in self.portal.store.recent_audit(10)])

    # ---------------------------------------------------------------- accounts
    def test_accounts_are_off_by_default(self):
        app = App(self.port)
        app.enroll()
        for path, body in (("/api/v1/login", {"login": "root", "password": "x"}),
                           ("/api/v1/signup", {"email": "a@example.com", "password": "x"}),
                           ("/api/v1/forgot", {"login": "root"})):
            st, data = app.call("POST", path, body)
            self.assertEqual((st, data["error"]), (404, "disabled"), path)

    def test_signup_in_the_app_links_the_device_and_premium_makes_it_pro(self):
        app = App(self.port)
        app.enroll()
        me = self.signup(app, "pro.user@example.com")
        self.assertEqual(me["account"]["email"], "pro.user@example.com")
        self.assertEqual((me["plan"], me["can_connect"]), ("free", False))  # signed in, but still Free
        user = self.portal.store.user_by_email("pro.user@example.com")
        self.portal.store.update_user(user["id"], plan="premium", plan_expires=int(time.time()) + 86400)
        me = app.me()
        self.assertEqual((me["plan"], me["can_connect"]), ("premium", True))
        self.settings(admob_enabled=1)
        st, data = app.call("POST", "/api/v1/reward/start", {"kind": "admob"})
        self.assertEqual((st, data["error"]), (409, "pro"))  # Pro needs no ads
        st, me = app.call("POST", "/api/v1/logout", {})
        self.assertEqual((me["account"], me["plan"]), (None, "free"))

    def test_app_login_lockout_device_limit_and_totp(self):
        app = App(self.port)
        app.enroll()
        self.signup(app, "limit.user@example.com")
        app.call("POST", "/api/v1/logout", {})
        self.settings(pro_device_limit=1)
        phone2 = App(self.port)
        phone2.enroll()
        st, data = phone2.call("POST", "/api/v1/login", {"login": "limit.user@example.com",
                                                         "password": "purple mountain river 7"})
        self.assertEqual(st, 200, data)
        st, data = app.call("POST", "/api/v1/login", {"login": "limit.user@example.com",
                                                      "password": "purple mountain river 7"})
        self.assertEqual((st, data["error"]), (409, "device_limit"))
        phone2.call("POST", "/api/v1/logout", {})
        # Wrong passwords from a device that never signed in to this account lock the shared bucket ...
        stranger = App(self.port)
        stranger.enroll()
        for _ in range(5):
            st, data = stranger.call("POST", "/api/v1/login", {"login": "limit.user@example.com", "password": "nope"})
            self.assertEqual((st, data["error"]), (401, "invalid"))
        st, _ = stranger.call("POST", "/api/v1/login", {"login": "limit.user@example.com",
                                                         "password": "purple mountain river 7"})
        self.assertEqual(st, 401)  # locked for unknown clients
        # ... but not the owner's own device, which has its own bucket.
        st, data = app.call("POST", "/api/v1/login", {"login": "limit.user@example.com",
                                                      "password": "purple mountain river 7"})
        self.assertEqual(st, 200, data)
        app.call("POST", "/api/v1/logout", {})
        user = self.portal.store.user_by_email("limit.user@example.com")
        secret = auth.new_totp_secret()
        self.portal.store.update_user(user["id"], totp_secret=secret, totp_enabled=1)
        st, data = app.call("POST", "/api/v1/login", {"login": "limit.user@example.com",
                                                      "password": "purple mountain river 7"})
        self.assertEqual((st, data["error"]), (401, "totp_required"))
        st, data = app.call("POST", "/api/v1/login", {"login": "limit.user@example.com",
                                                      "password": "purple mountain river 7",
                                                      "code": auth.hotp(secret, auth.totp_step(time.time()))})
        self.assertEqual(st, 200, data)
        self.assertIn("login_locked", [a["action"] for a in self.portal.store.recent_audit(30)])

    def test_password_reset_from_the_app(self):
        app = App(self.port)
        app.enroll()
        self.signup(app, "forgetful@example.com")
        # The sign-up code went out seconds ago and reset codes are throttled to one a minute: age it.
        uid = self.portal.store.user_by_email("forgetful@example.com")["id"]
        self.portal.store._exec("UPDATE password_resets SET created_at = created_at - 120 WHERE user_id = ?", (uid,))
        st, data = app.call("POST", "/api/v1/forgot", {"login": "forgetful@example.com"})
        self.assertEqual(st, 200, data)
        st, data = app.call("POST", "/api/v1/forgot", {"login": "nobody@example.com"})
        self.assertEqual(st, 200)  # same answer for unknown accounts
        mail = self.mails.wait("forgetful@example.com", 2)[-1]
        code = re.search(r"\b(\d{6})\b", mail["text"]).group(1)
        st, data = app.call("POST", "/api/v1/forgot/verify", {"login": "forgetful@example.com", "code": code,
                                                              "password": "brand new long passphrase"})
        self.assertEqual(st, 200, data)
        st, data = app.call("POST", "/api/v1/login", {"login": "forgetful@example.com",
                                                      "password": "brand new long passphrase"})
        self.assertEqual(st, 200, data)

    # ---------------------------------------------------------------- admin pages
    def test_admin_app_settings_and_devices_page(self):
        app = App(self.port)
        app.enroll()
        admin = Browser(self.port)
        st, h, _ = admin.login("root", self.admin_pw)
        if h.get("Location") == "/account/password":
            _, _, page = admin.get("/account/password")
            new = "admin passphrase for app tests"
            admin.post("/account/password", {"csrf": admin.csrf(page), "current": self.admin_pw, "new": new,
                                              "confirm": new})
            type(self).admin_pw = new
        _, _, page = admin.get("/admin/settings")
        self.assertIn(b'id="apps"', page)
        form = {"csrf": admin.csrf(page), "app_enrollment": "on", "admob_enabled": "on", "admob_require_ssv": "on",
                **{k: devices.APP_DEFAULTS[k] for k in devices.LIMITS}, "free_minutes": "45"}
        st, _, body = admin.post("/admin/settings/apps", form)
        self.assertEqual(st, 200)
        self.assertIn(b"App settings saved", body)
        s = self.portal.settings()
        self.assertEqual((s["free_minutes"], s["app_accounts"], s["admob_enabled"]), ("45", "0", "1"))
        st, _, body = admin.post("/admin/settings/apps", {**form, "free_minutes": "0"})
        self.assertIn(b"must be between", body)
        _, _, page = admin.get("/admin/devices")
        self.assertIn(app.profile["subject"].encode(), page)
        device = self.portal.store.vpn_device_by_subject(app.profile["subject"])
        st, _, _ = admin.post(f"/admin/devices/{device['id']}/disable", {"csrf": admin.csrf(page)})
        self.assertEqual(st, 200)
        self.portal.store.add_free_seconds(device["id"], 600)
        me = app.me()
        self.assertEqual((me["can_connect"], me["reason"]), (False, "device disabled by an administrator"))
        _, _, page = admin.get("/admin")
        st, _, body = admin.post("/admin/users", {"csrf": admin.csrf(page), "username": "d-sneaky", "role": "user",
                                                  "plan": "free"})
        self.assertIn(b"reserved for app devices", body)

    # ---------------------------------------------------------------- the VPN server enforces it
    def server_psk(self) -> bytes:
        with open(self.portal.cfg.psk_file, encoding="ascii") as f:
            return base64.b64decode(f.read().strip())

    async def test_psk_optional_server(self):
        """App devices (no PSK) connect only with psk_optional; PSK clients keep working; a wrong PSK never does."""
        app = App(self.port)
        await asyncio.to_thread(app.enroll)
        store = self.portal.store
        store.add_free_seconds(store.vpn_device_by_subject(app.profile["subject"])["id"], 600)
        ident = pki.Identity(pki.Certificate.from_pem(app.profile["certificate"]), app.key)
        trust = pki.TrustStore.load([self.portal.cfg.ca_certificate], peer_algs=DEFAULT_PEER_SIG_ALGS,
                                    ca_algs=DEFAULT_CA_SIG_ALGS + ("SLH-DSA-SHA2-128s",))
        server_id = pki.Identity.load(os.path.join(self.tmp, "server", "server.crt"),
                                      os.path.join(self.tmp, "server", "server.key"))
        psk = self.server_psk()
        cases = (  # (server accepts no-PSK clients, client's PSK, expected to connect, PSK in use)
            (False, None, False, None),        # default: a PSK server refuses clients without it (unchanged)
            (True, None, True, False),         # psk_optional: the app device connects without a PSK
            (True, psk, True, True),           # ... and a profile client still uses the PSK
            (True, os.urandom(32), False, None),  # a wrong PSK fails under both key sets
        )
        for optional, client_psk, connects, psk_used in cases:
            scfg = server_cfg(dataclasses.replace(crypto_cfg(psk=psk), psk_optional=optional),
                              addresses=["10.98.0.1/24"])
            server, client, _s_tun, _c_tun = await loopback_pair(
                None, scfg, client_identity=ident, server_identity=server_id, server_trust=trust,
                client_trust=trust, access=PortalAccess(os.path.join(self.tmp, "portal.db")),
                client_crypto=crypto_cfg(psk=client_psk))
            seen = []

            def spy(peer, result, now, _install=server.install, _seen=seen):
                _seen.append(result.psk_used)  # what the server's handshake reported
                return _install(peer, result, now)
            server.install = spy
            try:
                client.start_handshake(time.monotonic())
                if connects:
                    await asyncio.wait_for(client.connected.wait(), 10)
                    self.assertEqual(seen, [psk_used], (optional, client_psk is not None))
                else:
                    with self.assertRaises(asyncio.TimeoutError):
                        await asyncio.wait_for(client.connected.wait(), 1.5)
                    self.assertEqual(server.peers, {})
            finally:
                client.close()
                server.close()
                await asyncio.sleep(0.05)

    async def test_vpn_server_enforces_free_time_and_pro(self):
        app = App(self.port)
        await asyncio.to_thread(app.enroll)
        store = self.portal.store
        device = store.vpn_device_by_subject(app.profile["subject"])
        ident = pki.Identity(pki.Certificate.from_pem(app.profile["certificate"]), app.key)
        trust = pki.TrustStore.load([self.portal.cfg.ca_certificate], peer_algs=DEFAULT_PEER_SIG_ALGS,
                                    ca_algs=DEFAULT_CA_SIG_ALGS + ("SLH-DSA-SHA2-128s",))
        server_id = pki.Identity.load(os.path.join(self.tmp, "server", "server.crt"),
                                      os.path.join(self.tmp, "server", "server.key"))
        access = PortalAccess(os.path.join(self.tmp, "portal.db"))
        # The real setup: the server keeps its PSK for administrator-issued profiles and, with psk_optional,
        # also accepts app devices, which get no PSK.
        scfg = server_cfg(dataclasses.replace(crypto_cfg(psk=self.server_psk()), psk_optional=True),
                          addresses=["10.98.0.1/24"])
        server, client, s_tun, c_tun = await loopback_pair(
            None, scfg, client_identity=ident, server_identity=server_id, server_trust=trust, client_trust=trust,
            access=access, client_crypto=crypto_cfg())
        subject = app.profile["subject"]
        try:
            client.start_handshake(time.monotonic())  # Free with no time: refused
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(client.connected.wait(), 1.5)

            store.add_free_seconds(device["id"], 60)  # one watched ad later ...
            client.start_handshake(time.monotonic())
            await asyncio.wait_for(client.connected.wait(), 10)
            c_tun.inject(icmp_echo(app.profile["address"], "10.98.0.1", 1))
            await asyncio.wait_for(s_tun.written.get(), 5)

            store.update_vpn_device(device["id"], free_seconds=0)  # ... and the time runs out
            for _ in range(20):
                await asyncio.sleep(0.25)
                if subject not in server.peers:
                    break
            self.assertNotIn(subject, server.peers)

            # Signed in to a Premium account: connects with no free time at all.
            uid = store.create_user("prouser", "user", "premium passphrase 123", must_change=False)
            store.update_user(uid, plan="premium")
            store.update_vpn_device(device["id"], user_id=uid)
            client.connected.clear()
            client.start_handshake(time.monotonic())
            await asyncio.wait_for(client.connected.wait(), 10)
            # Premium DNS (the client itself keeps its first connection's settings until it reconnects).
            self.assertEqual(access.authorize(ident.cert).get("dns"), ["94.140.14.14", "94.140.15.15"])

            store.update_user(uid, enabled=0)  # disabling the account cuts its devices too
            for _ in range(20):
                await asyncio.sleep(0.25)
                if subject not in server.peers:
                    break
            self.assertNotIn(subject, server.peers)
        finally:
            client.close()
            server.close()
            await asyncio.sleep(0.05)


class TestAppClients(unittest.TestCase):
    """The Python client the apps use (account_client.py) and the Android entry points (android_client.py)."""

    @classmethod
    def setUpClass(cls):
        TestAppApi.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TestAppApi.tearDownClass.__func__(cls)

    def setUp(self):
        self.portal.store.set_settings({**devices.APP_DEFAULTS, "app_enrollment": "1", "app_accounts": "1",
                                        "admob_enabled": "1", "admob_require_ssv": "0"})
        self.url = f"http://127.0.0.1:{self.port}/"

    def test_android_enroll_writes_a_working_profile_and_returns_sealable_secrets(self):
        from pqvpn import android_client
        from pqvpn.config import load_client
        dest = os.path.join(self.tmp, "android-profile")
        out = json.loads(android_client.enroll_json(self.url, "", True, dest))
        self.assertTrue(out["ok"], out)
        self.assertEqual(sorted(os.listdir(dest)), ["ca.crt", "client.toml", "device.crt"])  # no key, no PSK on disk
        self.assertTrue(out["summary"]["enrolled"])
        self.assertTrue(out["secrets"]["key_pem"].startswith("-----BEGIN PRIVATE KEY-----"))
        self.assertEqual(out["secrets"]["psk"], "")  # app devices get no PSK
        cfg = load_client(os.path.join(dest, "client.toml"))
        self.assertEqual((cfg.server_name, cfg.crypto.psk), ("vpn.test", None))
        self.assertEqual(json.loads(android_client.load_profile_summary_json(dest))["summary"]["account"],
                         out["summary"]["account"])
        token = out["token"]
        me = json.loads(android_client.api_json(self.url, "", True, token, "GET", "/api/v1/me", ""))
        self.assertEqual((me["ok"], me["data"]["plan"]), (True, "free"))
        st = json.loads(android_client.api_json(self.url, "", True, token, "POST", "/api/v1/reward/start",
                                                json.dumps({"kind": "admob"})))
        claim = json.loads(android_client.api_json(self.url, "", True, token, "POST", "/api/v1/reward/claim",
                                                   json.dumps({"nonce": st["data"]["nonce"]})))
        self.assertTrue(claim["data"]["can_connect"])
        bad = json.loads(android_client.api_json(self.url, "", True, token, "POST", "/api/v1/enroll", "{}"))
        self.assertEqual((bad["ok"], bad["code"]), (False, "bad_request"))  # not on the allow-list
        denied = json.loads(android_client.api_json(self.url, "", True, "x" * 43, "GET", "/api/v1/me", ""))
        self.assertEqual((denied["status"], denied["code"]), (401, "unauthorized"))
        renewed = os.path.join(self.tmp, "android-renewed")
        self.portal.store._exec("UPDATE vpn_devices SET cert_expires = ? WHERE subject = ?",
                                (int(time.time()) + 86400, out["summary"]["account"]))  # due for renewal
        out2 = json.loads(android_client.renew_json(self.url, "", True, token, renewed))
        self.assertTrue(out2["ok"], out2)
        self.assertNotEqual(out2["secrets"]["key_pem"], out["secrets"]["key_pem"])
        self.assertEqual(out2["summary"]["tunnel_address"], out["summary"]["tunnel_address"])

    def test_https_only_unless_allowed_and_network_errors_are_reported(self):
        from pqvpn import account_client, android_client
        with self.assertRaises(ValueError):
            account_client.PortalClient(self.url)  # plain http refused unless explicitly allowed
        with self.assertRaises(ValueError):
            account_client.PortalClient("https://example.com/", pin="abcd")
        out = json.loads(android_client.enroll_json(self.url, "", False, os.path.join(self.tmp, "nope")))
        self.assertEqual((out["ok"], out["code"]), (False, "bad_profile"))
        out = json.loads(android_client.enroll_json("http://127.0.0.1:9/", "", True, os.path.join(self.tmp, "x")))
        self.assertEqual((out["ok"], out["code"]), (False, "network"))

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a TLS certificate")
    def test_certificate_pinning(self):
        import ssl
        import subprocess
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pqvpn import account_client
        d = tempfile.mkdtemp(prefix="pqvpn-pin-")
        try:
            crt, key = os.path.join(d, "tls.crt"), os.path.join(d, "tls.key")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=portal.test"],
                           check=True, capture_output=True)

            class Echo(BaseHTTPRequestHandler):
                def do_GET(self):
                    body = b'{"ok": true}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *a):
                    pass

            srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            url = f"https://127.0.0.1:{srv.server_address[1]}/"
            with open(crt, encoding="ascii") as f:
                pin = account_client.cert_pin(account_client.pem_to_der(f.read()))
            try:
                self.assertEqual(account_client.PortalClient(url, pin=pin).call("GET", "/x"), {"ok": True})
                with self.assertRaises(account_client.PortalError) as cm:
                    account_client.PortalClient(url, pin="0" * 64).call("GET", "/x")
                self.assertEqual(cm.exception.code, "pin_mismatch")
                with self.assertRaises(account_client.PortalError) as cm:  # unpinned: the self-signed cert fails
                    account_client.PortalClient(url).call("GET", "/x")
                self.assertEqual(cm.exception.code, "network")
            finally:
                srv.shutdown()
                srv.server_close()
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestDeviceUnits(unittest.TestCase):
    def test_subjects_and_settings(self):
        s = devices.new_subject()
        self.assertTrue(devices.is_device_subject(s))
        self.assertEqual(len(s), 26)
        self.assertFalse(devices.is_device_subject("alice"))
        self.assertFalse(devices.is_device_subject("d-short"))
        self.assertEqual(devices.number({"free_minutes": "100000"}, "free_minutes"), 24 * 60)
        self.assertEqual(devices.number({"free_minutes": "abc"}, "free_minutes"), 30)
        self.assertFalse(devices.enabled({}, "app_enrollment"))  # everything is off by default
        self.assertTrue(all(devices.APP_DEFAULTS[k] == "0" for k in
                            ("app_enrollment", "app_accounts", "admob_enabled", "web_ads_enabled", "web_ads_test")))


if __name__ == "__main__":
    unittest.main()
