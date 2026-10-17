"""The repository must not contain (and the scanner must detect) real key material."""

from __future__ import annotations

import base64
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, ROOT)

import secret_scan  # noqa: E402


class TestSecretScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqvpn-scan-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name: str, data: bytes) -> str:
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_detects_real_material_but_not_mentions(self):
        from pqvpn.crypto import ossl
        pem = ossl.private_to_pem(ossl.generate("ML-DSA-44"))
        psk = (base64.b64encode(os.urandom(32)).decode() + "\n").encode()
        real = [self.write("client.key", pem), self.write("psk.key", psk),
                # built at run time so this test file never contains a key-shaped literal itself
                self.write("sa.json", b'{"type": "service_account", "project_id": "x", "private_key": "-----BEGIN '
                           + b'PRIVATE KEY-----\\n' + base64.b64encode(os.urandom(60)) + b'"}'),
                self.write("portal.db", b"SQLite format 3\x00" + bytes(100))]
        found = {os.path.basename(p) for p, _ in secret_scan.scan_paths(real)}
        self.assertEqual(found, {"client.key", "psk.key", "sa.json", "portal.db"})

        harmless = [self.write("doc.md", b"paste -----BEGIN PRIVATE KEY-----... here"),
                    self.write("test.py", b"self.assertIn('-----BEGIN PRIVATE KEY-----', x)"),
                    self.write("ca.crt", b"-----BEGIN PQVPN CERTIFICATE-----\nAAAA\n-----END PQVPN CERTIFICATE-----\n")]
        self.assertEqual(secret_scan.scan_paths(harmless), [])

    def test_scans_inside_apk_and_nested_python_archives(self):
        from pqvpn.crypto import ossl
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("pkg/leaked.key", ossl.private_to_pem(ossl.generate("ML-DSA-44")))
        apk = os.path.join(self.tmp, "app.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("assets/ui/index.html", "<html></html>")
            z.writestr("assets/chaquopy/app.imy", inner.getvalue())
        hits = secret_scan.scan_paths([apk])
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0][0].endswith("app.imy!/pkg/leaked.key"))

    def test_repository_is_clean(self):
        """Everything `git add -A` would pick up must be free of secrets (ignored files are not scanned)."""
        try:
            files = secret_scan.candidate_files()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        old = os.getcwd()
        os.chdir(ROOT)
        try:
            findings = secret_scan.scan_paths(files)
        finally:
            os.chdir(old)
        self.assertEqual(findings, [], f"secrets would be committed: {[p for p, _ in findings]}")


class TestExampleConfigs(unittest.TestCase):
    """deploy/examples/*.example.toml must stay loadable by the real parsers and hold placeholders only."""

    def test_examples_parse_and_reference_secrets_by_path(self):
        from pqvpn import config
        d = os.path.join(ROOT, "deploy", "examples")
        s = config.load_server(os.path.join(d, "server.example.toml"))
        c = config.load_client(os.path.join(d, "client.example.toml"))
        p = config.load_portal(os.path.join(d, "portal.example.toml"))
        self.assertTrue(s.dns, "full-tunnel clients need a pushed DNS server")
        self.assertIsNone(s.crypto.psk)            # PSK is commented out: nothing secret is needed to parse
        self.assertTrue(c.server_host.startswith("<") and p.endpoint.startswith("<"))
        self.assertEqual(secret_scan.scan_paths([d]), [])


if __name__ == "__main__":
    unittest.main()
