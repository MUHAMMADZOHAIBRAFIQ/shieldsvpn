"""Admin console: the three product pages (Website, Browser extension, App) and their settings."""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.config import load_portal  # noqa: E402
from pqvpn.portal import products  # noqa: E402
from pqvpn.portal.service import portal_init  # noqa: E402
from pqvpn.portal.web import Portal  # noqa: E402
from pqvpn.protocol import RateLimiter  # noqa: E402
from tests.test_portal import Browser  # noqa: E402


class TestProductHelpers(unittest.TestCase):
    def test_clean_url(self):
        self.assertEqual(products.clean_url(" https://ShieldsVPN.vercel.app "), "https://shieldsvpn.vercel.app/")
        self.assertEqual(products.clean_url("https://example.com/site?x=1#y"), "https://example.com/site")
        self.assertEqual(products.clean_url(""), "")
        for bad in ("http://example.com/", "https://localhost/", "https://10.0.0.1/", "javascript:alert(1)",
                    "https://user:pw@example.com/", "https://exa mple.com/", "https://" + "a" * 300 + ".com/",
                    'https://example.com/"><script>'):
            with self.assertRaises(ValueError, msg=bad):
                products.clean_url(bad)
        hosts = products.STORES["extension_firefox_url"][1]
        self.assertTrue(products.clean_url("https://addons.mozilla.org/firefox/addon/shieldsvpn/", hosts))
        with self.assertRaises(ValueError):
            products.clean_url("https://evil.example/firefox/addon/shieldsvpn/", hosts)

    def test_page_urls_and_check(self):
        base = "https://shieldsvpn.vercel.app/"
        self.assertEqual(products.page_url(base, "/"), base)
        self.assertEqual(products.page_url(base, "/terms.html"), "https://shieldsvpn.vercel.app/terms.html")
        seen = []

        def fetch(url, timeout):
            seen.append(url)
            if url.endswith("/terms.html"):
                raise OSError("connection refused")
            return 404 if url.endswith("/delete-account.html") else 200

        out = products.check_pages(base, fetch=fetch)
        self.assertEqual(len(seen), 4)
        self.assertEqual([c["ok"] for c in out], [True, True, False, False])
        self.assertEqual(out[2]["status"], 0)
        self.assertIn("refused", out[2]["error"])

    def test_check_refuses_private_addresses(self):
        # A public name that resolves into the server's own network (DNS rebinding) is refused before connecting.
        private = [(2, 1, 6, "", ("192.168.1.5", 443))]
        with mock.patch.object(products.socket, "getaddrinfo", return_value=private):
            with self.assertRaises(ValueError):
                products._public_ip("rebind.example", 443)
            out = products.check_pages("https://rebind.example/", pages=(("Home", "/"),))
        self.assertEqual((out[0]["ok"], out[0]["status"]), (False, 0))
        self.assertIn("private network", out[0]["error"])
        public = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with mock.patch.object(products.socket, "getaddrinfo", return_value=public):
            self.assertEqual(products._public_ip("example.com", 443), "93.184.216.34")

    def test_extension_manifest(self):
        info = products.extension_info()
        self.assertIsNotNone(info)  # browser-extension/manifest.json is in this repository
        self.assertEqual(info["manifest_version"], 3)
        self.assertEqual(info["permissions"], ["nativeMessaging"])
        self.assertIsNone(products.extension_info(tempfile.mkdtemp(prefix="pqvpn-noext-")))


class TestAdminProductPages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pqvpn-products-")
        cls.admin_pw = portal_init(cls.tmp, server_name="vpn.test", endpoint="127.0.0.1:51820",
                                   subnet="10.98.0.0/24", admin="root", listen=["127.0.0.1:8800"],
                                   public_url="http://127.0.0.1:8800/", issuer="Test VPN", psk=True, nat="",
                                   ca_alg="SLH-DSA-SHA2-128s")
        cfg = load_portal(os.path.join(cls.tmp, "portal.toml"))
        cfg.listen = [("127.0.0.1", 0)]
        cfg.require_2fa_for_admins = False
        cls.portal = Portal(cfg)
        cls.portal.limiter = RateLimiter(rate=1000, burst=1000)
        cls.checked = []

        def fake_check(base, pages=products.WEBSITE_PAGES):
            cls.checked.append(base)
            return products.check_pages(base, pages, fetch=lambda url, t: 404 if "delete" in url else 200)

        cls.portal.check_pages = fake_check
        cls.port = int(cls.portal.start()[0].rsplit(":", 1)[1].strip("/"))
        s, now = cls.portal.store, int(time.time())
        ids = []
        for i, platform in enumerate(("android", "android", "windows")):
            d = s.create_vpn_device(f"d-{'abcdefghijklmnopqrstuvwx'[i] * 24}", f"hash{i}", platform, cfg.subnet,
                                    set(cfg.reserved_addresses), "198.51.100.7")
            ids.append(d["id"])
        s._exec("UPDATE vpn_devices SET free_seconds = 600 WHERE id = ?", (ids[0],))
        s._exec("INSERT INTO reward_grants (device_id, kind, nonce_hash, created_at, granted_at) "
                "VALUES (?, 'admob', 'n1', ?, ?)", (ids[0], now - 60, now - 30))
        s.publish_peers([{"username": "d-" + "a" * 24, "endpoint": "198.51.100.7:4000", "address": "10.98.0.2/32",
                          "suite": "", "key_alg": "ML-DSA-65", "connected_since": now, "last_handshake": now,
                          "rx_bytes": 0, "tx_bytes": 0}])

    @classmethod
    def tearDownClass(cls):
        cls.portal.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def admin(self) -> Browser:
        b = Browser(self.port)
        st, h, _ = b.login("root", self.admin_pw)
        if h.get("Location") == "/account/password":
            _, _, page = b.get("/account/password")
            new = "products passphrase for tests 1"
            b.post("/account/password", {"csrf": b.csrf(page), "current": self.admin_pw, "new": new,
                                         "confirm": new})
            type(self).admin_pw = new
        return b

    def test_dashboard_leads_with_the_three_products(self):
        _, _, page = self.admin().get("/admin")
        html = page.decode()
        cards = re.findall(r'<a class="product product--(\w+)" href="(/admin/\w+)"', html)
        self.assertEqual(cards, [("web", "/admin/website"), ("ext", "/admin/extension"), ("app", "/admin/app")])
        self.assertLess(html.index('class="products"'), html.index('id="users-table"'))
        self.assertIn("<b>2</b> phones", html)
        self.assertIn("<b>1</b> online", html)

    def test_pages_are_for_administrators_only(self):
        for path in ("/admin/website", "/admin/extension", "/admin/app"):
            st, h, _ = Browser(self.port).get(path)
            self.assertEqual(st, 303, path)
            self.assertTrue(h.get("Location", "").startswith("/login"), path)

    def test_app_page_counts(self):
        st, _, page = self.admin().get("/admin/app")
        html = page.decode()
        self.assertEqual(st, 200)
        self.assertRegex(html, r"Android phones</span>\s*<strong class=\"tile-num\">2<")
        self.assertRegex(html, r"Windows PCs</span><strong class=\"tile-num\">1<")
        self.assertRegex(html, r"Online now</span><strong class=\"tile-num\">1<")
        self.assertRegex(html, r"Ads watched today</span>\s*<strong class=\"tile-num\">1<")
        self.assertIn("<td>Android</td><td>2</td><td>1</td>", html)  # registered, online
        self.assertIn("Newest devices", html)
        self.assertIn("User Agreement", html)

    def test_website_address_and_page_check(self):
        b = self.admin()
        _, _, page = b.get("/admin/website")
        self.assertIn(b"set the address first", page)
        for bad in ("http://shieldsvpn.vercel.app/", "https://127.0.0.1/"):
            st, _, body = b.post("/admin/website", {"csrf": b.csrf(page), "website_url": bad})
            self.assertIn(b"Website address:", body)
        st, _, body = b.post("/admin/website", {"csrf": b.csrf(page), "website_url": "https://shieldsvpn.vercel.app"})
        self.assertIn(b"Website address saved.", body)
        self.assertEqual(self.portal.settings()["website_url"], "https://shieldsvpn.vercel.app/")
        self.assertIn(b"https://shieldsvpn.vercel.app/privacy.html", body)
        st, _, body = b.post("/admin/website/check", {"csrf": b.csrf(body)})
        self.assertEqual(self.checked[-1], "https://shieldsvpn.vercel.app/")
        self.assertEqual(body.count(b'<span class="pill on">200 OK</span>'), 3)
        self.assertIn(b"Not answering: Delete account.", body)
        actions = [a["action"] for a in self.portal.store.recent_audit(5)]
        self.assertIn("website_checked", actions)
        self.assertIn("website_settings_changed", actions)
        st, _, _ = b.post("/admin/website", {"website_url": "https://example.com/"})  # no CSRF field
        self.assertEqual(st, 403)

    def test_extension_store_pages(self):
        b = self.admin()
        _, _, page = b.get("/admin/extension")
        html = page.decode()
        self.assertIn("nativeMessaging", html)
        self.assertIn("0/3", html)
        form = {"csrf": b.csrf(page), "extension_chrome_url": "https://evil.example/detail/x",
                "extension_edge_url": "", "extension_firefox_url": ""}
        _, _, body = b.post("/admin/extension", form)
        self.assertIn(b"Chrome Web Store: the address must be on", body)
        form["extension_chrome_url"] = "https://chromewebstore.google.com/detail/shieldsvpn/abc"
        _, _, body = b.post("/admin/extension", {**form, "csrf": b.csrf(body)})
        self.assertIn(b"Store pages saved.", body)
        self.assertIn(b"1/3", body)
        self.assertIn(b'<span class="pill on">Published</span>', body)

    def test_stored_values_are_escaped(self):
        self.portal.store.set_settings({"extension_edge_url": '"><script>alert(1)</script>',
                                        "website_url": "https://ok.example/'\"><b>x"})
        try:
            for path in ("/admin/extension", "/admin/website", "/admin"):
                _, _, page = self.admin().get(path)
                self.assertNotIn(b"<script>alert(1)", page, path)
                self.assertNotIn(b"<b>x", page, path)
        finally:
            self.portal.store.set_settings({"extension_edge_url": "", "website_url": ""})


if __name__ == "__main__":
    unittest.main()
