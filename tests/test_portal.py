"""Portal tests: auth standards, QR codes, HTTP flows and VPN access control end to end."""

from __future__ import annotations

import asyncio
import base64
import http.client
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import pki  # noqa: E402
from pqvpn.config import load_client, load_portal  # noqa: E402
from pqvpn.crypto.suites import DEFAULT_CA_SIG_ALGS, DEFAULT_PEER_SIG_ALGS  # noqa: E402
from pqvpn.crypto import ossl  # noqa: E402
from pqvpn.portal import auth, firebase, mail, plans  # noqa: E402
from pqvpn.portal.access import PortalAccess  # noqa: E402
from pqvpn.portal.qr import QrCode  # noqa: E402
from pqvpn.portal.service import portal_init  # noqa: E402
from pqvpn.portal.store import Store  # noqa: E402
from pqvpn.portal.vault import Vault, VaultError  # noqa: E402
from pqvpn.portal.web import PORTAL_DEFAULTS, RESET_MAX_ATTEMPTS, Portal  # noqa: E402
from pqvpn.protocol import RateLimiter  # noqa: E402
from pqvpn.runner import crypto_cfg, icmp_echo, loopback_pair, server_cfg  # noqa: E402
from tests.fake_firestore import FakeGoogle, make_key  # noqa: E402

auth.SCRYPT_N = 1 << 14  # faster hashing in tests (the cost is stored in each hash)


class TestAuthStandards(unittest.TestCase):
    def test_rfc6238_vectors(self):
        secret = base64.b32encode(b"12345678901234567890").decode()
        for t, code in {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
                        1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}.items():
            self.assertEqual(auth.hotp(secret, t // 30, 8), code)

    def test_totp_window_and_replay(self):
        s, now = auth.new_totp_secret(), 1_700_000_000
        code = auth.hotp(s, auth.totp_step(now))
        step = auth.verify_totp(s, code, 0, now)
        self.assertIsNotNone(step)
        self.assertIsNone(auth.verify_totp(s, code, step, now))           # replay
        self.assertIsNone(auth.verify_totp(s, code, 0, now + 120))        # too old
        self.assertIsNone(auth.verify_totp(s, "000000", 0, now))

    def test_password_hashing_and_policy(self):
        h = auth.hash_password("a long passphrase")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(auth.verify_password("a long passphrase", h))
        self.assertFalse(auth.verify_password("a long passphrasE", h))
        self.assertFalse(auth.verify_password("x", None))
        self.assertTrue(auth.password_problems("short"))
        self.assertTrue(auth.password_problems("password123"))
        self.assertTrue(auth.password_problems("alice-is-great-2026", "alice"))
        self.assertEqual(auth.password_problems("correct horse battery staple"), [])


class TestQr(unittest.TestCase):
    def test_structure(self):
        q = QrCode(b"otpauth://totp/PQ%20VPN:alice?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=PQ%20VPN")
        n = q.size
        for x0, y0 in ((0, 0), (n - 7, 0), (0, n - 7)):  # finder patterns
            self.assertTrue(all(q.modules[y0][x0 + i] for i in range(7)))
            self.assertTrue(q.modules[y0 + 3][x0 + 3])
        self.assertIn("<svg", q.svg())

    @unittest.skipUnless(shutil.which("node") and os.environ.get("PQVPN_JSQR"), "set PQVPN_JSQR=<node_modules dir>")
    def test_independent_decoder(self):
        text = "otpauth://totp/PQ%20VPN:alice?secret=JBSWY3DPEHPK3PXP&issuer=PQ%20VPN"
        js = ("const jsQR=require('jsqr');const m=JSON.parse(process.argv[1]);const n=m.length,b=4,p=4,d=(n+2*b)*p;"
              "const a=new Uint8ClampedArray(d*d*4).fill(255);for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(m[y][x])"
              "for(let i=0;i<p;i++)for(let j=0;j<p;j++){const k=(((y+b)*p+i)*d+(x+b)*p+j)*4;a[k]=a[k+1]=a[k+2]=0;}"
              "const r=jsQR(a,d,d);process.stdout.write(r?r.data:'')")
        out = subprocess.run(["node", "-e", js, json.dumps(QrCode(text.encode()).modules)], capture_output=True,
                             text=True, env={**os.environ, "NODE_PATH": os.environ["PQVPN_JSQR"]})
        self.assertEqual(out.stdout, text)


class TestPlans(unittest.TestCase):
    def test_parse_dns(self):
        self.assertEqual(plans.parse_dns("1.1.1.1, 9.9.9.9;1.1.1.1 2606:4700:4700::1111"),
                         ["1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"])
        self.assertEqual(plans.parse_dns(""), [])
        with self.assertRaises(ValueError):
            plans.parse_dns("1.1.1.1, dns.google")
        with self.assertRaises(ValueError):
            plans.parse_dns("1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9")

    def test_effective_plan_and_dns_precedence(self):
        settings = {**plans.DEFAULT_SETTINGS, "dns_free_preset": "cloudflare"}
        now = 1_800_000_000
        free = {"plan": "free", "plan_expires": None, "custom_dns": None}
        prem = {"plan": "premium", "plan_expires": None, "custom_dns": None}
        expired = {"plan": "premium", "plan_expires": now - 1, "custom_dns": None}
        own = {"plan": "premium", "plan_expires": None, "custom_dns": "10.0.0.53"}
        self.assertEqual(plans.effective_plan(prem, now), "premium")
        self.assertEqual(plans.effective_plan({**prem, "plan_expires": now + 60}, now), "premium")
        self.assertEqual(plans.effective_plan(expired, now), "free")
        self.assertEqual(plans.dns_for(free, settings, now), ["1.1.1.1", "1.0.0.1"])
        self.assertEqual(plans.dns_for(prem, settings, now), ["94.140.14.14", "94.140.15.15"])  # AdGuard default
        self.assertEqual(plans.dns_for(expired, settings, now), ["1.1.1.1", "1.0.0.1"])
        self.assertEqual(plans.dns_for(own, settings, now), ["10.0.0.53"])
        custom = {**settings, "dns_premium_preset": "custom", "dns_premium_custom": "9.9.9.11"}
        self.assertEqual(plans.dns_for(prem, custom, now), ["9.9.9.11"])
        self.assertEqual(plans.dns_for(free, plans.DEFAULT_SETTINGS, now), [])  # server.toml default


class TestStoreMigration(unittest.TestCase):
    def test_old_database_is_upgraded(self):
        d = tempfile.mkdtemp(prefix="pqvpn-mig-")
        try:
            path = os.path.join(d, "portal.db")
            con = sqlite3.connect(path)  # the first-release users table, without the new columns
            con.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE
                COLLATE NOCASE, display_name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL, password_hash TEXT
                NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1, totp_secret TEXT, totp_enabled INTEGER
                NOT NULL DEFAULT 0, totp_last_step INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
                vpn_ip TEXT UNIQUE, active_serial TEXT, profile_issued_at INTEGER, failed_logins INTEGER NOT NULL
                DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
                last_login_at INTEGER);
                INSERT INTO users (username, role, password_hash, created_at) VALUES ('old', 'admin', 'x', 1);""")
            con.close()
            store = Store(path)
            Store(path)  # idempotent
            old = store.user_by_name("old")
            self.assertEqual((old["plan"], old["email"], old["plan_expires"]), ("free", None, None))
            store.update_user(old["id"], email="Old@Example.com", plan="premium")
            self.assertEqual(store.user_by_email("old@example.COM")["username"], "old")
            uid = store.create_user("new", "user", "a long passphrase here")
            with self.assertRaises(sqlite3.IntegrityError):  # emails are unique, case-insensitively
                store.update_user(uid, email="OLD@example.com")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestVault(unittest.TestCase):
    def test_seal_open_roundtrip_and_tamper(self):
        d = tempfile.mkdtemp(prefix="pqvpn-vault-")
        try:
            v = Vault(os.path.join(d, "k.key"))
            self.assertEqual(os.stat(os.path.join(d, "k.key")).st_size, 32)
            self.assertEqual(v.open("smtp_password", ""), "")
            self.assertEqual(v.seal("smtp_password", ""), "")
            sealed = v.seal("smtp_password", "hunter2 app pw")
            self.assertTrue(sealed.startswith("enc:v1:"))
            self.assertNotIn("hunter2", sealed)
            self.assertEqual(v.open("smtp_password", sealed), "hunter2 app pw")
            self.assertEqual(v.open("smtp_password", "legacy-plaintext"), "legacy-plaintext")  # pre-vault value
            with self.assertRaises(VaultError):  # ciphertext bound to its setting name (associated data)
                v.open("other_field", sealed)
            with self.assertRaises(VaultError):
                v.open("smtp_password", sealed[:-4] + ("AAAA" if sealed[-4:] != "AAAA" else "BBBB"))
            v2 = Vault(os.path.join(d, "k.key"))  # same key file -> still decryptable after a restart
            self.assertEqual(v2.open("smtp_password", sealed), "hunter2 app pw")
            with self.assertRaises(VaultError):  # a different key cannot read it
                Vault(os.path.join(d, "other.key")).open("smtp_password", sealed)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestMailGuards(unittest.TestCase):
    def test_internal_address_detection(self):
        for host in ("127.0.0.1", "localhost", "foo.localhost", "10.0.0.5", "192.168.1.1", "169.254.1.1",
                     "::1", "fd00::1", "0.0.0.0"):
            self.assertTrue(mail.internal_address(host), host)
        for host in ("smtp.gmail.com", "8.8.8.8", "1.1.1.1"):
            self.assertFalse(mail.internal_address(host), host)

    def test_pin_public_host_refuses_internal(self):
        with self.assertRaisesRegex(mail.MailError, "internal address"):
            mail.pin_public_host({"host": "127.0.0.1", "port": 25})
        with self.assertRaisesRegex(mail.MailError, "internal address"):
            mail.pin_public_host({"host": "localhost", "port": 25})


class TestMailer(unittest.TestCase):
    def test_transport_options(self):
        t = mail.smtp_transport({"smtp_host": "smtp.gmail.com", "smtp_port": "465", "smtp_security": "ssl",
                                 "smtp_user": "a@gmail.com", "smtp_password": "abcd"})
        self.assertEqual((t["port"], t["secure"], t["requireTLS"]), (465, True, False))
        t = mail.smtp_transport({"smtp_host": "smtp.example.com", "smtp_port": "587", "smtp_security": "starttls",
                                 "smtp_user": "a@example.com", "smtp_password": "abcd"})
        self.assertEqual((t["port"], t["secure"], t["requireTLS"]), (587, False, True))  # never plaintext
        self.assertTrue(mail.valid_email("muhammad.z+vpn@gmail.com"))
        for bad in ("no-at-sign", "a@b", "a@@b.com", "a b@c.com", "<a@b.com>"):
            self.assertFalse(mail.valid_email(bad), bad)

    def test_missing_node_is_reported(self):
        saved = os.environ.get("PQVPN_NODE")
        os.environ["PQVPN_NODE"] = os.path.join(tempfile.gettempdir(), "no-such-node-binary")
        try:
            if mail.nodemailer_installed():
                with self.assertRaisesRegex(mail.MailError, "cannot run Node.js"):
                    mail.send({"jsonTransport": True}, {"to": "a@example.com", "text": "x"})
        finally:
            if saved is None:
                os.environ.pop("PQVPN_NODE")
            else:
                os.environ["PQVPN_NODE"] = saved

    @unittest.skipUnless(mail.node_binary() and mail.nodemailer_installed(),
                         "needs Node.js + `npm ci` in pqvpn/portal/mailer")
    def test_nodemailer_builds_the_message(self):
        msg = mail.reset_code_message("PQ VPN", "alice", "042517", 10, "203.0.113.9")
        info = mail.send({"jsonTransport": True}, {"from": {"name": "PQ VPN", "address": "vpn@example.com"},
                                                    "to": "alice@example.com", **msg})
        built = json.loads(info["message"])
        self.assertEqual(built["to"][0]["address"], "alice@example.com")
        self.assertEqual(built["from"], {"address": "vpn@example.com", "name": "PQ VPN"})
        self.assertIn("042517", built["subject"])
        self.assertIn("042517", built["text"])
        self.assertIn("042517", built["html"])
        with self.assertRaises(mail.MailError):  # SMTP errors surface as MailError
            mail.send({"host": "127.0.0.1", "port": 1, "secure": True, "auth": {"user": "u", "pass": "p"}},
                      {"to": "alice@example.com", "text": "x"}, timeout=30, allow_internal=True)


class TestFirebaseUnit(unittest.TestCase):
    def test_value_encoding(self):
        enc = firebase.encode_value
        self.assertEqual(enc(None), {"nullValue": None})
        self.assertEqual(enc(True), {"booleanValue": True})
        self.assertEqual(enc(42), {"integerValue": "42"})  # int64 travels as a string in the REST API
        self.assertEqual(enc("x"), {"stringValue": "x"})
        self.assertEqual(enc(firebase.Timestamp(0)), {"timestampValue": "1970-01-01T00:00:00Z"})
        self.assertEqual(enc(["1.1.1.1"]), {"arrayValue": {"values": [{"stringValue": "1.1.1.1"}]}})

    def test_key_validation(self):
        key, _ = make_key("https://oauth2.googleapis.com/token")
        self.assertEqual(firebase.parse_key(json.dumps(key))["project_id"], "pq-vpn-test")
        no_token_uri = json.dumps({k: v for k, v in key.items() if k != "token_uri"})
        self.assertEqual(firebase.parse_key(no_token_uri)["project_id"], "pq-vpn-test")  # may be absent
        for text, msg in (("nope", "not valid JSON"), ('{"type": "authorized_user"}', "not a service-account"),
                          (json.dumps({**key, "client_email": ""}), "no client_email"),
                          (json.dumps({**key, "project_id": "evil project!"}), "not a valid Google Cloud project"),
                          (json.dumps({**key, "token_uri": "http://169.254.169.254/token"}), "not Google's token"),
                          (json.dumps({**key, "private_key": "garbage"}), "cannot be read"),
                          (json.dumps({**key, "private_key": ossl.private_to_pem(ossl.generate("EC", "P-256"))
                                       .decode()}), "not an RSA key")):
            with self.assertRaisesRegex(firebase.FirebaseError, msg):
                firebase.parse_key(text)

    def test_client_ignores_key_token_uri(self):
        key, _ = make_key("https://oauth2.googleapis.com/token")
        c = firebase.Client({**key, "token_uri": "http://attacker.example/steal"})
        self.assertEqual(c.token_uri, firebase.TOKEN_URI)  # the key's token_uri is never used as a URL

    def test_no_secrets_are_mirrored(self):
        user = {"id": 1, "username": "alice", "display_name": "A", "role": "admin", "password_hash": "scrypt$SECRET1",
                "must_change_password": 0, "totp_secret": "SECRET2", "totp_enabled": 1, "totp_last_step": 9,
                "enabled": 1, "vpn_ip": "10.0.0.2", "active_serial": "ab", "profile_issued_at": 1,
                "failed_logins": 0, "locked_until": 0, "created_at": 1, "last_login_at": 2, "email": "a@b.co",
                "plan": "premium", "plan_expires": None, "custom_dns": None}
        settings = {**mail.DEFAULT_SETTINGS, **plans.DEFAULT_SETTINGS, "smtp_password": "SECRET3"}
        docs = json.dumps([firebase.user_doc(user, settings, 0), firebase.settings_doc(settings)], default=repr)
        for secret in ("SECRET1", "SECRET2", "SECRET3", "password_hash", "totp_secret", "smtp_password"):
            self.assertNotIn(secret, docs)

    @unittest.skipUnless(shutil.which("node"), "needs Node.js")
    def test_rs256_assertion_verifies_independently(self):
        key, pkey = make_key("https://oauth2.googleapis.com/token")
        jwt = firebase.Client(key)._assertion()
        h64, c64, s64 = jwt.split(".")
        js = ("const c=require('crypto');const [p,d,s]=JSON.parse(process.argv[1]);"
              "process.stdout.write(String(c.verify('RSA-SHA256',Buffer.from(d),p,Buffer.from(s,'base64url'))))")
        out = subprocess.run(["node", "-e", js, json.dumps([ossl.public_to_pem(pkey).decode(), f"{h64}.{c64}", s64])],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.stdout, "true", out.stderr)
        claims = json.loads(base64.urlsafe_b64decode(c64 + "=="))
        self.assertEqual((claims["scope"], claims["aud"]), (firebase.SCOPE, "https://oauth2.googleapis.com/token"))
        self.assertEqual(claims["exp"] - claims["iat"], 3600)


def _doc_path(write: dict) -> str:
    """Firestore commit write -> "collection/doc"."""
    name = write["update"]["name"] if "update" in write else write["delete"]
    return name.split("/documents/", 1)[1]


class MailCapture:
    """Stands in for Nodemailer in the HTTP tests."""

    def __init__(self):
        self.sent: list[dict] = []
        self.cv = threading.Condition()
        self.fail = ""

    def __call__(self, transport, message, timeout=60, allow_internal=False):
        if self.fail:
            raise mail.MailError(self.fail)
        with self.cv:
            self.sent.append({"transport": transport, **message})
            self.cv.notify_all()
        return {"messageId": "<test@pqvpn>"}

    def wait(self, to: str, count: int, timeout: float = 10) -> list[dict]:
        def mine():
            return [m for m in self.sent if m["to"] == to]
        with self.cv:
            self.cv.wait_for(lambda: len(mine()) >= count, timeout)
            return mine()


class Browser:
    def __init__(self, port: int):
        self.port, self.cookies = port, {}

    def req(self, method, path, form=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        body = urllib.parse.urlencode(form).encode() if form is not None else None
        h = {"Host": f"127.0.0.1:{self.port}"}
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        for v in r.headers.get_all("Set-Cookie") or []:
            name, _, rest = v.partition("=")
            if "Max-Age=0" in v:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = rest.split(";")[0]
        conn.close()
        return r.status, r.headers, data

    def get(self, path):
        return self.req("GET", path)

    def post(self, path, form, **kw):
        return self.req("POST", path, form, **kw)

    @staticmethod
    def csrf(html: bytes) -> str:
        return re.search(rb'name="csrf" value="([^"]+)"', html).group(1).decode()

    def login(self, user, password):
        return self.post("/login", {"username": user, "password": password})


class TestPortalEndToEnd(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqvpn-portal-")
        cls.admin_pw = portal_init(cls.tmp, server_name="vpn.test", endpoint="127.0.0.1:51820",
                                   subnet="10.99.0.0/24", admin="root", listen=["127.0.0.1:8800"],
                                   public_url="http://127.0.0.1:8800/", issuer="Test VPN", psk=True, nat="",
                                   ca_alg="SLH-DSA-SHA2-128s")
        cfg = load_portal(os.path.join(cls.tmp, "portal.toml"))
        cfg.listen = [("127.0.0.1", 0)]
        # These end-to-end flows predate enforced admin 2FA (now the default); test_require_2fa_for_admins
        # covers the enforcement on its own.
        cfg.require_2fa_for_admins = False
        cls.portal = Portal(cfg)
        cls.portal.limiter = RateLimiter(rate=1000, burst=1000)  # all test traffic comes from 127.0.0.1
        cls.mails = MailCapture()
        cls.portal.mailer = cls.mails
        cls.portal.store.set_settings({"smtp_user": "vpn@example.com", "smtp_password": "app-password"})
        # Most tests exercise user self-service; test_admins_only_portal covers the default (admins only).
        cls.portal.store.set_settings({"portal_access": "everyone"})
        cls.port = int(cls.portal.start()[0].rsplit(":", 1)[1].strip("/"))

    @classmethod
    def tearDownClass(cls):
        cls.portal.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def admin(self) -> Browser:
        b = Browser(self.port)
        st, h, _ = b.login("root", self.admin_pw)
        if h.get("Location") == "/account/password":
            _, _, page = b.get("/account/password")
            new = "admin passphrase for tests 1"
            st, h, _ = b.post("/account/password", {"csrf": b.csrf(page), "current": self.admin_pw, "new": new,
                                                    "confirm": new})
            self.assertEqual((st, h.get("Location")), (303, "/"))
            type(self).admin_pw = new
        return b

    def create_user(self, b: Browser, name: str, display: str = "", email: str = "") -> str:
        _, _, page = b.get("/admin")
        st, _, body = b.post("/admin/users", {"csrf": b.csrf(page), "username": name, "display_name": display,
                                              "role": "user", "email": email, "plan": "free"})
        self.assertEqual(st, 200)
        return re.search(rb'<code class="secret">([^<]+)</code>', body).group(1).decode()

    def first_login(self, name: str, temp: str, new: str) -> Browser:
        u = Browser(self.port)
        st, h, _ = u.login(name, temp)
        self.assertEqual((st, h.get("Location")), (303, "/account/password"))
        _, _, page = u.get("/")  # forced password change blocks everything else
        _, _, page = u.get("/account/password")
        st, h, _ = u.post("/account/password", {"csrf": u.csrf(page), "current": temp, "new": new, "confirm": new})
        self.assertEqual(st, 303)
        return u

    # ---------------------------------------------------------------- web security
    def test_requires_login_and_security_headers(self):
        b = Browser(self.port)
        st, h, _ = b.get("/")
        self.assertEqual((st, h["Location"]), (303, "/login"))
        st, h, body = b.get("/login")
        self.assertEqual(st, 200)
        self.assertIn("script-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertIn(b"<svg", body)  # logo
        st, h, _ = b.get("/api/status")
        self.assertEqual(st, 401)

    def test_session_cookie_flags_csrf_origin_logout(self):
        b = Browser(self.port)
        st, h, _ = b.login("root", self.admin_pw)
        if h.get("Location") == "/account/password":
            self.admin()
            b = Browser(self.port)
            st, h, _ = b.login("root", self.admin_pw)
        cookie = h["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        _, _, page = b.get("/admin")
        st, _, _ = b.post("/admin/users", {"username": "nocsrf", "role": "user"})
        self.assertEqual(st, 403)
        st, _, _ = b.post("/admin/users", {"csrf": b.csrf(page), "username": "x1", "role": "user"},
                          headers={"Origin": "http://evil.example"})
        self.assertEqual(st, 403)
        saved = dict(b.cookies)
        st, _, _ = b.post("/logout", {"csrf": b.csrf(page)})
        self.assertEqual(st, 303)
        b.cookies = saved  # replaying the old cookie must not work
        st, h, _ = b.get("/admin")
        self.assertEqual((st, h["Location"]), (303, "/login?next=/admin"))  # bounced to login, returns to /admin

    def test_browser_origin_header_and_referrer_policy(self):
        # Real browsers send "Origin: null" on form POSTs when the page's policy is "no-referrer", which made
        # every browser sign-in fail with "Cross-site request blocked".  The policy must let the origin through.
        st, h, _ = Browser(self.port).get("/login")
        self.assertEqual(h["Referrer-Policy"], "same-origin")
        self.admin()  # makes sure the first-login password change has happened
        origin = {"Origin": f"http://127.0.0.1:{self.port}", "Referer": f"http://127.0.0.1:{self.port}/login"}
        st, h, _ = Browser(self.port).post("/login", {"username": "root", "password": self.admin_pw},
                                           headers=origin)
        self.assertEqual(st, 303)
        st, _, body = Browser(self.port).post("/login", {"username": "root", "password": self.admin_pw},
                                              headers={"Origin": "null"})
        self.assertEqual(st, 403)  # opaque origins (sandboxed frames, file:// pages) stay blocked
        self.assertIn(b"Cross-site request blocked", body)

    def test_admin_dashboard_and_controls(self):
        a = self.admin()
        st, _, home = a.get("/")  # admins land on the personal dashboard, not the admin console
        self.assertEqual(st, 200)
        self.assertNotIn(b"Admin dashboard", home)
        self.assertNotIn(b"/admin/settings", home)  # admin area is not linked anywhere in the normal UI
        st, _, page = a.get("/admin")  # the console is reached only by typing /admin
        self.assertEqual(st, 200)
        for part in (b"Admin dashboard", b'id="users-table"', b"Recent activity", b'href="/admin#add"',
                     b'id="peer-count"', b"Download my VPN profile", b'data-filter="users-table"', b'id="add"'):
            self.assertIn(part, page)
        temp = self.create_user(a, "nora", email="nora@example.com")
        u = self.first_login("nora", temp, "copper lantern river 3")  # "All users" mode in this fixture
        _, _, upage = u.get("/")
        self.assertIn(b"Welcome", upage)
        self.assertNotIn(b"Admin dashboard", upage)
        nora = self.portal.store.user_by_name("nora")

        # Lock nora with wrong passwords; the admin unlocks her from the dashboard and stays on the dashboard.
        for _ in range(5):
            Browser(self.port).login("nora", "wrong password 123")
        _, _, page = a.get("/admin")
        self.assertIn(f'/admin/users/{nora["id"]}/unlock"'.encode(), page)
        st, _, body = a.post(f"/admin/users/{nora['id']}/unlock", {"csrf": a.csrf(page), "back": "dashboard"})
        self.assertIn(b"nora unlocked.", body)
        self.assertIn(b"Admin dashboard", body)
        self.assertEqual(Browser(self.port).login("nora", "copper lantern river 3")[0], 303)

        # End nora's portal sessions from her page.
        _, _, page = a.get(f"/admin/users/{nora['id']}")
        self.assertIn(b"End portal sessions", page)
        st, _, body = a.post(f"/admin/users/{nora['id']}/signout", {"csrf": a.csrf(page), "back": "user"})
        self.assertIn(b"signed out of the portal everywhere", body)
        self.assertEqual(u.get("/")[1]["Location"], "/login")

        # Delete from the dashboard returns to the dashboard.
        st, _, body = a.post(f"/admin/users/{nora['id']}/delete", {"csrf": a.csrf(page), "back": "dashboard"})
        self.assertIn(b"nora deleted", body)
        self.assertIn(b"Admin dashboard", body)
        self.assertIsNone(self.portal.store.user_by_name("nora"))
        _, _, page = a.get("/admin/audit")
        for event in (b"user_unlocked", b"sessions_revoked", b"user_deleted"):
            self.assertIn(event, page)
        self.assertIn(b'data-filter="audit-table"', page)

    def test_lockout_and_no_enumeration(self):
        a = self.admin()
        temp = self.create_user(a, "mallory")
        b = Browser(self.port)
        for _ in range(5):
            st, _, body = b.login("mallory", "wrong password 123")
            self.assertEqual(st, 401)
        st, _, body2 = b.login("mallory", temp)  # correct password, but locked now
        self.assertEqual(st, 401)
        st, _, body3 = b.login("nobody-here", "whatever pass")
        self.assertEqual(st, 401)
        msg = rb'<p class="alert">([^<]+)</p>'
        self.assertEqual(re.search(msg, body2).group(1), re.search(msg, body3).group(1))

    def test_login_rate_limit_per_ip(self):
        saved = self.portal.limiter
        self.portal.limiter = RateLimiter(rate=0.001, burst=3)
        try:
            codes = [Browser(self.port).login("root", "wrong password 123")[0] for _ in range(5)]
        finally:
            self.portal.limiter = saved
        self.assertEqual(codes[:3], [401, 401, 401])
        self.assertEqual(codes[3:], [429, 429])

    def test_html_escaping(self):
        a = self.admin()
        self.create_user(a, "xss", display='<script>alert(1)</script>')
        _, _, page = a.get("/admin")
        self.assertNotIn(b"<script>alert(1)</script>", page)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_admin_area_unlinked_but_reachable_by_url(self):
        a = self.admin()
        # No admin links anywhere in the chrome or on the landing page.
        for path in ("/", "/account"):
            _, _, page = a.get(path)
            self.assertNotIn(b'href="/admin"', page)
            self.assertNotIn(b'href="/admin/settings"', page)
            self.assertNotIn(b'href="/admin/audit"', page)
        # But typing the address works for an admin...
        for path in ("/admin", "/admin/settings", "/admin/audit"):
            self.assertEqual(a.get(path)[0], 200, path)
        # ...and a logged-out visit to /admin bounces through login and lands back on /admin (safe next only).
        v = Browser(self.port)
        st, h, _ = v.get("/admin")
        self.assertEqual((st, h["Location"]), (303, "/login?next=/admin"))
        _, _, page = v.get("/login?next=/admin")
        self.assertIn(b'name="next" value="/admin"', page)
        st, h, _ = v.post("/login", {"csrf": "", "username": "root", "password": self.admin_pw, "next": "/admin"})
        # root has no 2FA in this fixture, so this completes straight away
        self.assertEqual((st, h["Location"]), (303, "/admin"))
        # An off-site next is ignored (open-redirect guard).
        v2 = Browser(self.port)
        st, h, _ = v2.post("/login", {"username": "root", "password": self.admin_pw,
                                      "next": "https://evil.example/x"})
        self.assertEqual((st, h["Location"]), (303, "/"))

    def test_host_header_rejected(self):
        # A DNS-rebinding page sets a foreign Host; the portal must refuse before doing anything.
        st, _, body = Browser(self.port).req("GET", "/login", headers={"Host": "rebind.attacker.example"})
        self.assertEqual(st, 421)
        st, _, _ = Browser(self.port).req("POST", "/login",
                                          {"username": "root", "password": self.admin_pw},
                                          headers={"Host": "rebind.attacker.example",
                                                   "Origin": "http://rebind.attacker.example"})
        self.assertEqual(st, 421)
        st, _, _ = Browser(self.port).req("GET", "/login", headers={"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(st, 200)  # the real host still works

    def test_non_ascii_csrf_and_code_do_not_500(self):
        a = self.admin()
        _, _, page = a.get("/admin")
        st, _, _ = a.post("/admin/users", {"csrf": "é" * 43, "username": "nope", "role": "user"})
        self.assertEqual(st, 403)  # not 500
        self.assertIsNone(self.portal.store.user_by_name("nope"))
        arabic = "١٢٣٤٥٦"
        st, _, _ = a.post("/account/2fa", {"csrf": a.csrf(page), "code": arabic})  # no TOTP pending -> redirect
        self.assertIn(st, (303, 200))

    def test_device_cookie_scopes_lockout(self):
        a = self.admin()
        temp = self.create_user(a, "lockme")
        owner = self.first_login("lockme", temp, "copper river twenty two")  # now a known device
        for _ in range(5):
            self.assertEqual(Browser(self.port).login("lockme", "wrong password here")[0], 401)
        # A stranger (no device cookie) has locked only the "unknown client" bucket.
        self.assertEqual(Browser(self.port).login("lockme", "copper river twenty two")[0], 401)
        owner.post("/logout", {"csrf": Browser.csrf(owner.get("/")[2])})  # keeps the device cookie
        st, h, _ = owner.login("lockme", "copper river twenty two")  # same browser, still trusted
        self.assertEqual((st, h.get("Location")), (303, "/"))
        uid = self.portal.store.user_by_name("lockme")["id"]
        _, _, page = a.get(f"/admin/users/{uid}")
        a.post(f"/admin/users/{uid}/unlock", {"csrf": a.csrf(page), "back": "user"})
        self.assertEqual(Browser(self.port).login("lockme", "copper river twenty two")[0], 303)

    def test_require_2fa_for_admins_enforced(self):
        a = self.admin()
        _, _, page = a.get("/admin")
        st, _, body = a.post("/admin/users", {"csrf": a.csrf(page), "username": "newadmin", "role": "admin",
                                              "plan": "free", "email": ""})
        temp = re.search(rb'<code class="secret">([^<]+)</code>', body).group(1).decode()
        self.portal.cfg.require_2fa_for_admins = True
        try:
            b = Browser(self.port)
            st, h, _ = b.login("newadmin", temp)
            self.assertEqual(h["Location"], "/account/password")  # forced password change first
            _, _, page = b.get("/account/password")
            st, h, _ = b.post("/account/password", {"csrf": b.csrf(page), "current": temp,
                                                    "new": "ferric garden lantern 9", "confirm": "ferric garden lantern 9"})
            self.assertEqual(st, 303)
            st, h, _ = b.get("/")  # now 2FA setup is forced before anything else
            self.assertEqual(h["Location"], "/account/2fa")
            self.assertEqual(b.get("/admin")[1]["Location"], "/account/2fa")
            _, _, page = b.get("/account/2fa")
            secret = re.search(rb'<code class="secret">([A-Z2-7 ]+)</code>', page).group(1).decode().replace(" ", "")
            st, _, _ = b.post("/account/2fa", {"csrf": b.csrf(page), "code": auth.hotp(secret, auth.totp_step())})
            self.assertEqual(b.get("/")[0], 200)  # enrolled -> full access
        finally:
            self.portal.cfg.require_2fa_for_admins = False

    def test_smtp_internal_address_blocked(self):
        a = self.admin()
        saved = {k: self.portal.store.settings().get(k, "") for k in
                 ("smtp_host", "smtp_port", "smtp_security", "smtp_user", "mail_from_name")}
        self.portal.mailer = mail.send  # exercise the real SSRF guard, not the capture fake
        try:
            _, _, page = a.get("/admin/settings")
            a.post("/admin/settings/email", {"csrf": a.csrf(page), "smtp_host": "127.0.0.1", "smtp_port": "25",
                                             "smtp_security": "ssl", "smtp_user": "a@b.co", "mail_from_name": "",
                                             "smtp_password": "secretpw"})
            st, _, body = a.post("/admin/settings/email/test", {"csrf": a.csrf(page), "to": "a@b.co"})
            self.assertIn(b"internal address", body)
        finally:
            self.portal.mailer = self.mails
            self.portal.store.set_settings({**saved, "smtp_password": "app-password"})

    def test_firebase_rejects_foreign_token_uri(self):
        a = self.admin()
        _, _, page = a.get("/admin/settings")
        bad, _ = make_key()
        bad = {**bad, "token_uri": "http://169.254.169.254/latest/token"}
        st, _, body = a.post("/admin/settings/firebase/connect", {"csrf": a.csrf(page), "key_json": json.dumps(bad)})
        self.assertIn(b"not Google&#x27;s token", body)
        self.assertFalse(os.path.exists(self.portal.mirror.key_path))

    # ---------------------------------------------------------------- 2FA
    def test_totp_enrolment_and_login(self):
        a = self.admin()
        temp = self.create_user(a, "carol")
        u = self.first_login("carol", temp, "blue harbour evening 7")
        _, _, page = u.get("/account/2fa")
        self.assertIn(b'aria-label="QR code"', page)
        secret = re.search(rb'<code class="secret">([A-Z2-7 ]+)</code>', page).group(1).decode().replace(" ", "")
        code = auth.hotp(secret, auth.totp_step())
        st, _, body = u.post("/account/2fa", {"csrf": u.csrf(page), "code": code})
        self.assertIn(b"Two-factor authentication is on", body)
        v = Browser(self.port)
        st, h, _ = v.login("carol", "blue harbour evening 7")
        self.assertEqual(h["Location"], "/login/2fa")
        st, h, _ = v.get("/")
        self.assertEqual(h["Location"], "/login/2fa")  # half-authenticated sessions cannot see anything
        _, _, page = v.get("/login/2fa")
        st, _, _ = v.post("/login/2fa", {"csrf": v.csrf(page), "code": code})  # replay of the enrolment code
        self.assertEqual(st, 401)
        nxt = auth.hotp(secret, auth.totp_step() + 1)
        st, h, _ = v.post("/login/2fa", {"csrf": v.csrf(page), "code": nxt})
        self.assertEqual((st, h["Location"]), (303, "/"))
        st, _, _ = v.get("/")
        self.assertEqual(st, 200)

    # ---------------------------------------------------------------- Firebase mirror
    def test_firebase_mirror(self):
        fake = FakeGoogle()
        mirror = self.portal.mirror
        mirror.endpoint = f"{fake.url}/v1"
        mirror.token_uri = f"{fake.url}/token"  # the pasted key still carries Google's URL; the portal pins this
        key, pkey = make_key()
        fake.trust(key, pkey)
        a = self.admin()
        try:
            _, _, page = a.get("/admin/settings")
            self.assertIn(b"Firebase (Firestore mirror)", page)
            self.assertIn(b"Not set up", page)
            st, _, body = a.post("/admin/settings/firebase/connect", {"csrf": a.csrf(page), "key_json": "nope"})
            self.assertIn(b"not valid JSON", body)
            stranger, _ = make_key()  # signed by a key Google does not know
            st, _, body = a.post("/admin/settings/firebase/connect",
                                 {"csrf": a.csrf(page), "key_json": json.dumps(stranger)})
            self.assertIn(b"Firebase rejected the connection", body)
            self.assertFalse(os.path.exists(mirror.key_path))  # rejected keys are not kept

            fake.firestore_error = (404, {"error": {"code": 404, "status": "NOT_FOUND", "message":
                                                    "The database (default) does not exist for project pq-vpn-test"}})
            st, _, body = a.post("/admin/settings/firebase/connect", {"csrf": a.csrf(page), "key_json": json.dumps(key)})
            self.assertIn(b"The key works and was saved, but the first sync failed", body)
            self.assertIn(b"create the database first", body)
            fake.firestore_error = None

            st, _, body = a.post("/admin/settings/firebase/connect", {"csrf": a.csrf(page), "key_json": json.dumps(key)})
            self.assertIn(b"Connected to Firebase project <strong>pq-vpn-test</strong>", body)
            self.assertIn(b"Syncing", body)
            self.assertNotIn(key["private_key"].encode()[30:80], body)  # the key is never shown again
            self.assertEqual(fake.value("users/root", "role"), "admin")
            self.assertNotIn("password_hash", fake.docs["users/root"])
            self.assertNotIn("smtp_password", fake.docs["settings/portal"])
            self.assertEqual(fake.value("settings/portal", "smtp_user"), "vpn@example.com")
            self.assertIn("online", fake.docs["status/server"])
            audit_ids = [r["id"] for r in self.portal.store.audit_after(0, 100000)]
            mirrored = sorted(int(k.split("/")[1]) for k in fake.docs if k.startswith("audit/"))
            self.assertEqual(mirrored, audit_ids[:len(mirrored)])
            self.assertGreaterEqual(len(mirrored), len(audit_ids) - 1)  # the "connected" event itself comes next

            # Nothing changed -> nothing written (only the new audit row about connecting, if any).
            mirror.sync_once()
            self.assertEqual(mirror.sync_once(), 0)

            # A plan change rewrites that one user (plus the audit row and the Premium count).
            temp = self.create_user(a, "olga", email="olga@example.com")
            mirror.sync_once()
            olga = self.portal.store.user_by_name("olga")
            _, _, page = a.get(f"/admin/users/{olga['id']}")
            a.post(f"/admin/users/{olga['id']}/edit", {"csrf": a.csrf(page), "display_name": "Olga", "role": "user",
                                                        "email": "olga@example.com", "plan": "premium",
                                                        "plan_expires": "", "custom_dns": ""})
            mirror.sync_once()
            last = {_doc_path(w) for w in fake.commits[-1]}
            self.assertIn("users/olga", last)
            self.assertNotIn("users/root", last)
            self.assertEqual(fake.value("users/olga", "plan_in_effect"), "premium")
            self.assertEqual(fake.value("users/olga", "dns"), ["94.140.14.14", "94.140.15.15"])

            # Live sessions: appear, traffic counters do not cause writes each pass, disappear on disconnect.
            peer = {"username": "olga", "endpoint": "203.0.113.5:4000", "address": "10.99.0.9/32",
                    "suite": "MLKEM768-X25519_CHACHA20POLY1305_SHA384", "key_alg": "ML-DSA-65",
                    "connected_since": int(time.time()), "last_handshake": int(time.time()), "rx_bytes": 1,
                    "tx_bytes": 2}
            self.portal.store.publish_peers([peer])
            mirror.sync_once()
            self.assertEqual(fake.value("connections/olga", "endpoint"), "203.0.113.5:4000")
            self.portal.store.publish_peers([{**peer, "rx_bytes": 99999}])
            self.assertEqual(mirror.sync_once(), 0)
            self.portal.store.publish_peers([])
            mirror.sync_once()
            self.assertNotIn("connections/olga", fake.docs)

            # Deleting a user deletes the document; a fresh mirror (portal restart) removes stale documents
            # and does not upload the audit log again.
            a.post(f"/admin/users/{olga['id']}/delete", {"csrf": a.csrf(page)})
            mirror.sync_once()
            self.assertNotIn("users/olga", fake.docs)
            fake.docs["users/ghost"] = {"username": {"stringValue": "ghost"}}
            fresh = firebase.Mirror(self.portal.store, mirror.key_path, self.portal.settings, {}, f"{fake.url}/v1",
                                    token_uri=f"{fake.url}/token")
            commits = len(fake.commits)
            fresh.sync_once()
            self.assertNotIn("users/ghost", fake.docs)
            self.assertFalse(any(_doc_path(w).startswith("audit/") for c in fake.commits[commits:] for w in c))

            _, _, page = a.get("/admin/settings")
            st, _, body = a.post("/admin/settings/firebase/pause", {"csrf": a.csrf(page)})
            self.assertIn(b"paused", body)
            self.assertFalse(mirror.enabled())
            a.post("/admin/settings/firebase/resume", {"csrf": a.csrf(page)})
            self.assertTrue(mirror.enabled())
            _, _, page = a.get("/admin")
            self.assertIn(b"Firebase mirror", page)
        finally:
            _, _, page = a.get("/admin/settings")
            st, _, body = a.post("/admin/settings/firebase/remove", {"csrf": a.csrf(page)})
            fake.stop()
        self.assertIn(b"Firebase key removed", body)
        self.assertFalse(os.path.exists(mirror.key_path))
        _, _, page = a.get("/admin/audit")
        for event in (b"firebase_connected", b"firebase_connect_failed", b"firebase_paused", b"firebase_key_removed"):
            self.assertIn(event, page)

    # ---------------------------------------------------------------- forgot password
    @staticmethod
    def _code(message: dict) -> str:
        return re.search(r"\b(\d{6})\b", message["text"]).group(1)

    def _forgot(self, login: str):
        b = Browser(self.port)
        st, h, _ = b.post("/forgot", {"login": login})
        return b, st, h

    def test_forgot_password_with_emailed_code(self):
        a = self.admin()
        temp = self.create_user(a, "dave", email="dave@example.com")
        old = self.first_login("dave", temp, "first orange kettle 42")
        st, _, page = Browser(self.port).get("/login")
        self.assertIn(b'href="/forgot"', page)

        # Unknown and known accounts get the same answer; only the real one gets a code.
        _, st1, h1 = self._forgot("nobody-at-all")
        b, st2, h2 = self._forgot("dave")
        self.assertEqual((st1, st2), (303, 303))
        self.assertEqual(h2["Location"], "/forgot/verify?login=dave")
        self.assertTrue(h1["Location"].startswith("/forgot/verify?"))
        first = self.mails.wait("dave@example.com", 1)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["from"], {"name": "Test VPN", "address": "vpn@example.com"})
        code = self._code(first[0])
        self.assertIn(code, first[0]["subject"])
        self._forgot("dave")  # a second request within a minute sends nothing (anti mail-bombing)
        time.sleep(0.5)
        self.assertEqual(len(self.mails.wait("dave@example.com", 1)), 1)
        _, _, page = b.get(h2["Location"])
        self.assertIn(b"6-digit code", page)

        wrong = "000000" if code != "000000" else "111111"
        st, _, body = b.post("/forgot/verify", {"login": "dave", "code": wrong, "new": "x", "confirm": "x"})
        self.assertEqual(st, 400)
        self.assertIn(b"not valid or has expired", body)
        st, _, body = b.post("/forgot/verify", {"login": "dave", "code": code, "new": "brand new passphrase 1",
                                                "confirm": "different passphrase 2"})
        self.assertEqual(st, 400)
        self.assertIn(b"do not match", body)
        self.assertIn(f'value="{code}"'.encode(), body)  # the code is kept for the retry
        st, _, body = b.post("/forgot/verify", {"login": "dave", "code": code, "new": "password123",
                                                "confirm": "password123"})
        self.assertIn(b"commonly used", body)
        st, h, _ = b.post("/forgot/verify", {"login": "dave", "code": code, "new": "brand new passphrase 1",
                                             "confirm": "brand new passphrase 1"})
        self.assertEqual((st, h["Location"]), (303, "/login?reset=done"))
        _, _, page = b.get("/login?reset=done")
        self.assertIn(b"Your password was changed", page)

        st, h, _ = old.get("/")  # every existing session was revoked
        self.assertEqual(h["Location"], "/login")
        self.assertEqual(Browser(self.port).login("dave", "first orange kettle 42")[0], 401)
        st, h, _ = Browser(self.port).login("dave", "brand new passphrase 1")
        self.assertEqual((st, h["Location"]), (303, "/"))
        st, _, _ = b.post("/forgot/verify", {"login": "dave", "code": code, "new": "another passphrase 3",
                                             "confirm": "another passphrase 3"})
        self.assertEqual(st, 400)  # single use
        notice = self.mails.wait("dave@example.com", 2)[1]
        self.assertIn("password was changed", notice["subject"])

        _, _, page = a.get("/admin/audit")
        for event in (b"password_reset_requested", b"password_reset_not_sent", b"password_reset_code_failed",
                      b"password_reset_by_email", b"email_sent"):
            self.assertIn(event, page)

    def test_forgot_password_by_email_and_attempt_limit(self):
        a = self.admin()
        self.create_user(a, "fiona", email="Fiona@Example.com")
        store = self.portal.store
        store.update_user(store.user_by_name("fiona")["id"], must_change_password=0)
        b, st, h = self._forgot("fiona@example.com")  # lookup by email, case-insensitive
        self.assertEqual(st, 303)
        code = self._code(self.mails.wait("Fiona@Example.com", 1)[0])
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(RESET_MAX_ATTEMPTS):  # enough wrong guesses burn the code
            b.post("/forgot/verify", {"login": "fiona@example.com", "code": wrong, "new": "x", "confirm": "x"})
        st, _, _ = b.post("/forgot/verify", {"login": "fiona@example.com", "code": code,
                                             "new": "fiona fresh passphrase", "confirm": "fiona fresh passphrase"})
        self.assertEqual(st, 400)

    def test_forgot_password_without_email_setup(self):
        store = self.portal.store
        saved = store.settings()["smtp_password"]
        store.set_settings({"smtp_password": ""})
        try:
            _, _, page = Browser(self.port).get("/forgot")
            self.assertIn(b"not set up yet", page)
            self.assertNotIn(b'action="/forgot"', page)
        finally:
            store.set_settings({"smtp_password": saved})

    # ---------------------------------------------------------------- admin: edit users, plans, settings
    def test_admin_edit_user_plan_and_dns(self):
        a = self.admin()
        self.create_user(a, "erin", email="erin@example.com")
        self.create_user(a, "gina", email="gina@example.com")
        uid = self.portal.store.user_by_name("erin")["id"]
        _, _, page = a.get(f"/admin/users/{uid}")
        self.assertIn(b"Profile &amp; plan", page)
        form = {"csrf": a.csrf(page), "display_name": "Erin E", "email": "gina@example.com", "role": "user",
                "plan": "premium", "plan_expires": "", "custom_dns": ""}
        st, _, body = a.post(f"/admin/users/{uid}/edit", form)
        self.assertIn(b"already used by another account", body)
        self.assertIn(b'value="Erin E"', body)  # the form keeps what the admin typed
        st, _, body = a.post(f"/admin/users/{uid}/edit", {**form, "email": "erin@example.com",
                                                          "custom_dns": "1.2.3.4, nope"})
        self.assertIn(b"not an IP address", body)
        st, _, body = a.post(f"/admin/users/{uid}/edit", {**form, "email": "erin@example.com",
                                                          "plan_expires": "2999-12-31"})
        self.assertIn(b"Saved:", body)
        erin = self.portal.store.user(uid)
        self.assertEqual((erin["display_name"], erin["plan"]), ("Erin E", "premium"))
        self.assertGreater(erin["plan_expires"], time.time())
        self.assertIn(b'class="badge premium"', body)
        self.assertIn(b'value="2999-12-31"', body)  # shows the last Premium day, not the day after
        st, _, body = a.post(f"/admin/users/{uid}/edit", {**form, "email": "erin@example.com",
                                                          "plan_expires": "2999-12-31"})
        self.assertIn(b"No changes.", body)

        access = PortalAccess(os.path.join(self.tmp, "portal.db"))
        self.portal.store.update_user(uid, active_serial="ab" * 16)
        cert = types.SimpleNamespace(subject="erin", serial_hex="ab" * 16)
        self.assertEqual(access.authorize(cert), {"dns": ["94.140.14.14", "94.140.15.15"]})  # premium default

        _, _, page = a.get("/admin/settings")
        st, _, body = a.post("/admin/settings/dns", {"csrf": a.csrf(page), "dns_free_preset": "cloudflare",
                                                     "dns_free_custom": "", "dns_premium_preset": "custom",
                                                     "dns_premium_custom": "9.9.9.11 149.112.112.11"})
        self.assertIn(b"DNS saved", body)
        self.assertEqual(access.authorize(cert), {"dns": ["9.9.9.11", "149.112.112.11"]})
        self.portal.store.update_user(uid, plan_expires=int(time.time()) - 1)  # premium ran out -> free DNS
        self.assertEqual(access.authorize(cert), {"dns": ["1.1.1.1", "1.0.0.1"]})
        st, _, body = a.post(f"/admin/users/{uid}/edit", {**form, "email": "erin@example.com", "plan": "free",
                                                          "custom_dns": "10.9.9.9"})
        self.assertEqual(access.authorize(cert), {"dns": ["10.9.9.9"]})
        _, _, body = a.post("/admin/settings/dns", {"csrf": a.csrf(page), "dns_free_preset": "default",
                                                    "dns_free_custom": "", "dns_premium_preset": "adguard",
                                                    "dns_premium_custom": ""})
        self.assertIn(b"DNS saved", body)

        # An admin cannot demote themselves; regular users cannot reach the admin pages.
        root = self.portal.store.user_by_name("root")
        _, _, page = a.get(f"/admin/users/{root['id']}")
        self.assertIn(b"cannot remove your own administrator role", page)
        a.post(f"/admin/users/{root['id']}/edit", {"csrf": a.csrf(page), "display_name": "Administrator",
                                                    "role": "user", "plan": "free", "email": ""})
        self.assertEqual(self.portal.store.user(root["id"])["role"], "admin")
        temp = self.create_user(a, "hank")
        u = self.first_login("hank", temp, "quiet meadow lantern 5")
        _, _, page = u.get("/")
        self.assertIn(b"Your plan", page)
        for path in ("/admin/settings", f"/admin/users/{uid}"):
            self.assertEqual(u.get(path)[0], 403)
        self.assertEqual(u.post("/admin/settings/dns", {"csrf": u.csrf(page), "dns_free_preset": "google"})[0], 403)

        _, _, page = a.get("/admin/audit")
        self.assertIn(b"user_updated", page)
        self.assertIn(b"dns_settings_changed", page)

    def test_admin_email_settings_and_test_message(self):
        a = self.admin()
        _, _, page = a.get("/admin/settings")
        self.assertIn(b"Email (password recovery)", page)
        self.assertNotIn(b"app-password", page)  # the SMTP password is write-only
        form = {"csrf": a.csrf(page), "smtp_host": "smtp.gmail.com", "smtp_port": "587", "smtp_security": "starttls",
                "smtp_user": "owner@example.com", "mail_from_name": "My VPN", "smtp_password": ""}
        st, _, body = a.post("/admin/settings/email", {**form, "smtp_host": "bad host!"})
        self.assertIn(b"host name", body)
        st, _, body = a.post("/admin/settings/email", form)
        self.assertIn(b"Email settings saved", body)
        s = self.portal.settings()  # decrypts secret settings
        self.assertEqual((s["smtp_port"], s["smtp_security"], s["smtp_password"]), ("587", "starttls", "app-password"))
        st, _, body = a.post("/admin/settings/email", {**form, "smtp_password": "abcd efgh ijkl mnop"})
        self.assertEqual(self.portal.settings()["smtp_password"], "abcdefghijklmnop")
        raw = self.portal.store.settings()["smtp_password"]  # stored sealed, never plaintext
        self.assertTrue(raw.startswith("enc:v1:") and "abcdefghijklmnop" not in raw)
        st, _, body = a.post("/admin/settings/email/test", {"csrf": a.csrf(page), "to": "owner@example.com"})
        self.assertIn(b"Test email sent", body)
        sent = self.mails.wait("owner@example.com", 1)[-1]
        self.assertEqual(sent["from"], {"name": "My VPN", "address": "owner@example.com"})
        self.assertEqual(sent["transport"]["port"], 587)
        self.mails.fail = "Invalid login: 535-5.7.8 Username and Password not accepted"
        try:
            st, _, body = a.post("/admin/settings/email/test", {"csrf": a.csrf(page), "to": "owner@example.com"})
            self.assertIn(b"Sending failed: Invalid login", body)
        finally:
            self.mails.fail = ""
        self.portal.store.set_settings({"smtp_host": "smtp.gmail.com", "smtp_port": "465", "smtp_security": "ssl",
                                        "smtp_user": "vpn@example.com", "mail_from_name": "",
                                        "smtp_password": "app-password"})

    def test_sign_in_with_email(self):
        a = self.admin()
        temp = self.create_user(a, "jane", email="Jane.Doe@Example.com")
        self.first_login("jane", temp, "violet harbour kite 4")
        st, h, _ = Browser(self.port).login("jane.doe@example.com", "violet harbour kite 4")  # case-insensitive
        self.assertEqual((st, h["Location"]), (303, "/"))
        msg = rb'<p class="alert">([^<]+)</p>'
        st, _, wrong = Browser(self.port).login("jane.doe@example.com", "not the password 1")
        st2, _, unknown = Browser(self.port).login("nobody@example.com", "not the password 1")
        self.assertEqual((st, st2), (401, 401))
        self.assertEqual(re.search(msg, wrong).group(1), re.search(msg, unknown).group(1))

    def test_admins_only_portal(self):
        self.assertEqual(PORTAL_DEFAULTS["portal_access"], "admins")  # fresh portals: administrators only
        a = self.admin()
        temp = self.create_user(a, "kim", email="kim@example.com")
        u = self.first_login("kim", temp, "amber window falcon 6")  # signed in while "All users" is on
        self.assertEqual(u.get("/")[0], 200)
        _, _, page = a.get("/admin/settings")
        self.assertIn(b"Portal access", page)
        try:
            st, _, body = a.post("/admin/settings/access", {"csrf": a.csrf(page), "portal_access": "admins"})
            self.assertIn(b"Only administrators can sign in now", body)
            st, h, _ = u.get("/")  # kim's existing session is dead
            self.assertEqual((st, h["Location"]), (303, "/login"))
            self.assertEqual(u.get("/api/status")[0], 401)
            st, _, body = Browser(self.port).login("kim", "amber window falcon 6")
            self.assertEqual(st, 403)
            self.assertIn(b"restricted to administrators", body)
            st, _, body = Browser(self.port).login("kim", "wrong password here")  # wrong password: generic
            self.assertEqual(st, 401)
            _, _, page = Browser(self.port).get("/login")
            self.assertIn(b"Administrators only", page)
            st, h, _ = Browser(self.port).login("root", self.admin_pw)  # admins still get in
            self.assertEqual((st, h["Location"]), (303, "/"))

            before = len(self.mails.wait("kim@example.com", 0))
            self._forgot("kim")  # no reset code for accounts that cannot sign in
            time.sleep(0.5)
            self.assertEqual(len(self.mails.wait("kim@example.com", 0)), before)

            _, _, page = a.get("/admin")
            st, _, body = a.post("/admin/users", {"csrf": a.csrf(page), "username": "lee", "role": "user",
                                                  "plan": "free", "email": ""})
            self.assertIn(b"VPN user <strong>lee</strong> created", body)
            self.assertNotIn(b'<code class="secret">', body)  # no portal password for VPN-only users
            lee = self.portal.store.user_by_name("lee")["id"]
            self.assertNotIn(f'/admin/users/{lee}/reset-password"'.encode(), body)
            st, _, body = a.post("/admin/users", {"csrf": a.csrf(page), "username": "max", "role": "admin",
                                                  "plan": "free", "email": ""})
            self.assertIn(b'<code class="secret">', body)  # a new administrator does get one
            _, _, page = a.get("/admin/audit")
            self.assertIn(b"login_denied", page)
            self.assertIn(b"portal_access_changed", page)
        finally:
            _, _, page = a.get("/admin/settings")
            a.post("/admin/settings/access", {"csrf": a.csrf(page), "portal_access": "everyone"})
        self.assertEqual(Browser(self.port).login("kim", "amber window falcon 6")[0], 303)

    def test_account_recovery_email(self):
        a = self.admin()
        temp = self.create_user(a, "ivan")
        u = self.first_login("ivan", temp, "silver tram morning 8")
        _, _, page = u.get("/")
        self.assertIn(b"recovery email", page)
        _, _, page = u.get("/account")
        st, _, body = u.post("/account/email", {"csrf": u.csrf(page), "email": "ivan@example.com",
                                                "password": "wrong password here"})
        self.assertIn(b"current password is incorrect", body)
        st, _, body = u.post("/account/email", {"csrf": u.csrf(page), "email": "ivan@example.com",
                                                "password": "silver tram morning 8"})
        self.assertIn(b"Recovery email saved", body)
        self.assertEqual(self.portal.store.user_by_name("ivan")["email"], "ivan@example.com")

    # ---------------------------------------------------------------- profiles + VPN access control
    def _unzip_profile(self, data: bytes) -> str:
        d = tempfile.mkdtemp(dir=self.tmp)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(d)
            (top,) = {n.split("/")[0] for n in z.namelist()}
        return os.path.join(d, top)

    async def test_profile_download_connect_status_and_revocation(self):
        a = await asyncio.to_thread(self.admin)
        temp = await asyncio.to_thread(self.create_user, a, "alice")
        u = await asyncio.to_thread(self.first_login, "alice", temp, "green valley sunrise 9")
        store = self.portal.store
        store.update_user(store.user_by_name("alice")["id"], plan="premium")
        store.set_settings({"dns_premium_preset": "quad9"})
        _, _, page = await asyncio.to_thread(u.get, "/")
        st, h, data = await asyncio.to_thread(u.post, "/profile", {"csrf": u.csrf(page)})
        self.assertEqual(st, 200)
        self.assertEqual(h["Content-Type"], "application/zip")
        prof = self._unzip_profile(data)
        self.assertEqual(sorted(os.listdir(prof)), ["README.txt", "alice.crt", "alice.key", "ca.crt", "client.toml",
                                                    "psk.key"])
        ccfg = load_client(os.path.join(prof, "client.toml"))
        self.assertEqual(ccfg.server_name, "vpn.test")
        ident = pki.Identity.load(ccfg.certificate, ccfg.private_key)

        trust = pki.TrustStore.load(ccfg.ca, peer_algs=DEFAULT_PEER_SIG_ALGS,
                                    ca_algs=DEFAULT_CA_SIG_ALGS + ("SLH-DSA-SHA2-128s",))
        server_id = pki.Identity.load(os.path.join(self.tmp, "server", "server.crt"),
                                      os.path.join(self.tmp, "server", "server.key"))
        access = PortalAccess(os.path.join(self.tmp, "portal.db"), "http://10.99.0.1:8800/")
        scfg = server_cfg(crypto_cfg(psk=ccfg.crypto.psk), addresses=["10.99.0.1/24"])
        server, client, s_tun, c_tun = await loopback_pair(
            None, scfg, client_identity=ident, server_identity=server_id, server_trust=trust, client_trust=trust,
            access=access, client_crypto=crypto_cfg(psk=ccfg.crypto.psk))
        try:
            client.start_handshake(time.monotonic())
            await asyncio.wait_for(client.connected.wait(), 10)
            self.assertEqual(client.server_config.get("portal"), "http://10.99.0.1:8800/")
            self.assertEqual(client.server_config.get("dns"), ["9.9.9.9", "149.112.112.112"])  # Premium DNS
            c_tun.inject(icmp_echo(ident.cert.addresses[0].split("/")[0], "10.99.0.1", 1))
            await asyncio.wait_for(s_tun.written.get(), 5)

            await asyncio.sleep(2.5)  # server publishes live status
            st, _, body = await asyncio.to_thread(u.get, "/api/status")
            status = json.loads(body)
            self.assertTrue(status["server_online"])
            self.assertEqual(status["me"]["username"], "alice")
            self.assertIn("MLKEM768", status["me"]["suite"])

            # Admin disables alice -> the server cuts her session within one status interval.
            _, _, page = await asyncio.to_thread(a.get, "/admin")
            uid = re.search(rb'action="/admin/users/(\d+)/disable"[^>]*data-confirm="Disable alice', page).group(1)
            st, _, _ = await asyncio.to_thread(a.post, f"/admin/users/{uid.decode()}/disable", {"csrf": a.csrf(page)})
            self.assertEqual(st, 200)
            for _ in range(20):
                await asyncio.sleep(0.25)
                if "alice" not in server.peers:
                    break
            self.assertNotIn("alice", server.peers)
            st, h, _ = await asyncio.to_thread(Browser(self.port).login, "alice", "green valley sunrise 9")
            self.assertEqual(st, 401)  # disabled accounts cannot sign in either
            client.connected.clear()
            client.start_handshake(time.monotonic())
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(client.connected.wait(), 1.5)

            # Re-enable, then a NEW profile supersedes the old certificate.
            _, _, page = await asyncio.to_thread(a.get, "/admin")
            await asyncio.to_thread(a.post, f"/admin/users/{uid.decode()}/enable", {"csrf": a.csrf(page)})
            await asyncio.to_thread(a.post, f"/admin/users/{uid.decode()}/profile", {"csrf": a.csrf(page)})
            client.connected.clear()
            client.start_handshake(time.monotonic())
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(client.connected.wait(), 1.5)
            _, _, page = await asyncio.to_thread(a.get, "/admin/audit")
            for event in (b"profile_issued", b"user_disabled", b"user_enabled", b"login_disabled"):
                self.assertIn(event, page)
        finally:
            client.close()
            server.close()
            await asyncio.sleep(0.05)


if __name__ == "__main__":
    unittest.main()
