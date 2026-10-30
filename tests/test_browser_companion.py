"""Browser extension companion: the native-messaging host, the tray app's local control channel, the per-user
installation, and the extension build (permissions, no inline script)."""

from __future__ import annotations

import asyncio
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn import control, native_host  # noqa: E402
from tools import build_extension  # noqa: E402

CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"


class LoopThread:
    """An asyncio loop on a thread, like the tray app's VPN loop."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(5)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


class TestControlChannel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pqvpn-control-")
        self.path = os.path.join(self.tmp, control.FILE)
        self.calls: list[str] = []
        self.loop = LoopThread()
        self.server = control.ControlServer(self._handler, self.path, {"config": "C:/x/client.toml"})
        self.port = self.loop.run(self.server.start())

    def tearDown(self):
        self.loop.loop.call_soon_threadsafe(self.server.close)
        self.loop.stop()

    def _handler(self, cmd: str) -> dict:
        self.calls.append(cmd)
        return {"state": "connected", "server": "vpn.test"}

    def raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), 5) as s:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            out = b""
            while chunk := s.recv(4096):
                out += chunk
            return out

    def test_commands_need_the_token(self):
        info = control.read_info(self.path)
        self.assertEqual((info["port"], info["config"]), (self.port, "C:/x/client.toml"))
        self.assertEqual(len(info["token"]), 43)  # 256 bits
        self.assertEqual(control.request("status", self.path), {"running": True, "ok": True, "state": "connected",
                                                                "server": "vpn.test"})
        control.request("connect", self.path)
        self.assertEqual(self.calls, ["status", "connect"])
        for line in (json.dumps({"token": "guess", "cmd": "connect"}), json.dumps({"cmd": "connect"}),
                     json.dumps(["not", "an", "object"])):
            self.assertIn(b"unauthorized", self.raw(line.encode() + b"\n"))
        self.assertIn(b"unknown command", self.raw(json.dumps({"token": info["token"], "cmd": "export_keys"})
                                                   .encode() + b"\n"))
        self.assertEqual(self.raw(b"x" * (control.MAX_LINE * 2) + b"\n"), b"")  # oversized: hang up
        self.assertEqual(self.raw(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"), b"")  # a web request: nothing
        self.assertEqual(self.calls, ["status", "connect"])  # none of the bad requests reached the app

    def test_stale_or_missing_file_means_not_running(self):
        self.assertEqual(control.request("status", os.path.join(self.tmp, "missing.json")),
                         {"ok": True, "running": False})
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            dead = s.getsockname()[1]
        stale = os.path.join(self.tmp, "stale.json")
        with open(stale, "w") as f:
            json.dump({"port": dead, "token": "t"}, f)
        self.assertEqual(control.request("status", stale), {"ok": True, "running": False})
        self.loop.loop.call_soon_threadsafe(self.server.close)
        self.loop.run(asyncio.sleep(0.05))
        self.assertFalse(os.path.exists(self.path))  # removed when the tray app exits


class TestNativeHost(unittest.TestCase):
    def frame(self, obj) -> bytes:
        data = json.dumps(obj).encode()
        return struct.pack("=I", len(data)) + data

    def test_framing_and_commands(self):
        tmp = tempfile.mkdtemp(prefix="pqvpn-nh-")
        path = os.path.join(tmp, control.FILE)
        out = io.BytesIO()
        rc = native_host.serve(io.BytesIO(self.frame({"cmd": "status"}) + self.frame({"cmd": "rm -rf"})), out, path)
        self.assertEqual(rc, 0)
        out.seek(0)
        self.assertEqual(native_host.read_message(out), {"ok": True, "running": False})
        self.assertEqual(native_host.read_message(out), {"ok": False, "error": "unknown command"})
        self.assertIsNone(native_host.read_message(out))
        huge = io.BytesIO(struct.pack("=I", native_host.MAX_MESSAGE + 1))
        with self.assertRaises(ValueError):
            native_host.read_message(huge)

    def test_launch_and_open_use_a_profile(self):
        tmp = tempfile.mkdtemp(prefix="pqvpn-nh-")
        path = os.path.join(tmp, control.FILE)
        started = []
        # The fallback profile lives in %LOCALAPPDATA%\pqvpn\native-host.json: keep this PC's real one out of the test.
        app_dir = mock.patch.object(native_host, "app_dir", return_value=tmp)
        app_dir.start()
        self.addCleanup(app_dir.stop)
        self.assertIn("no ShieldsVPN profile", native_host.handle({"cmd": "launch"}, path,
                                                                 lambda *a: started.append(a))["error"])
        config = os.path.join(tmp, "client.toml")
        open(config, "w").close()
        with open(path, "w") as f:
            json.dump({"port": 1, "token": "t", "config": config}, f)
        self.assertTrue(native_host.handle({"cmd": "launch"}, path, lambda *a: started.append(a))["starting"])
        native_host.handle({"cmd": "open"}, path, lambda *a: started.append(a))
        self.assertEqual(started, [("tray", config), ("app", config)])

    def test_install_writes_restricted_manifests(self):
        tmp = tempfile.mkdtemp(prefix="pqvpn-nh-")
        reg = {}
        files = native_host.install([CHROME_ID], "companion@shieldsvpn.app", None, tmp, reg.__setitem__)
        chromium = json.load(open(next(f for f in files if f.endswith(".chromium.json"))))
        firefox = json.load(open(next(f for f in files if f.endswith(".firefox.json"))))
        self.assertEqual(chromium["allowed_origins"], [f"chrome-extension://{CHROME_ID}/"])
        self.assertEqual(firefox["allowed_extensions"], ["companion@shieldsvpn.app"])
        self.assertEqual(chromium["name"], native_host.HOST_NAME)
        self.assertEqual(set(reg), {*native_host.CHROMIUM_KEYS, native_host.FIREFOX_KEY})
        self.assertIn("-m pqvpn native-host", open(chromium["path"]).read())
        for bad in (["*"], ["chrome-extension://x/"], ["ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"]):
            with self.assertRaises(ValueError):
                native_host.install(bad, "", None, tmp, reg.__setitem__)
        with self.assertRaises(ValueError):
            native_host.install([], "bad id with spaces", None, tmp, reg.__setitem__)


class TestExtensionBuild(unittest.TestCase):
    def test_build_for_each_store(self):
        out = tempfile.mkdtemp(prefix="pqvpn-ext-")
        built = build_extension.build(out, "companion@shieldsvpn.app")
        self.assertEqual(len([b for b in built if b.endswith(".zip")]), 2)
        for name in ("chromium", "firefox"):
            m = json.load(open(os.path.join(out, name, "manifest.json")))
            self.assertEqual(m["manifest_version"], 3)
            self.assertEqual(m["permissions"], ["nativeMessaging"])  # nothing else: no websites, tabs or history
            self.assertNotIn("host_permissions", m)
            for size in (16, 32, 48, 128):
                with open(os.path.join(out, name, "icons", f"icon-{size}.png"), "rb") as f:
                    self.assertEqual(f.read(8), b"\x89PNG\r\n\x1a\n")
        ff = json.load(open(os.path.join(out, "firefox", "manifest.json")))
        self.assertEqual(ff["browser_specific_settings"]["gecko"]["id"], "companion@shieldsvpn.app")
        html = open(os.path.join(out, "chromium", "popup.html")).read()
        self.assertNotRegex(html, r"<script>|\son[a-z]+=")  # no inline script or event handlers (MV3 CSP)
        js = open(os.path.join(out, "chromium", "popup.js")).read()
        self.assertNotIn("innerHTML", js)
        with zipfile.ZipFile(next(b for b in built if b.endswith("chromium-1.0.0.zip"))) as z:
            self.assertIn("manifest.json", z.namelist())


if __name__ == "__main__":
    unittest.main()
