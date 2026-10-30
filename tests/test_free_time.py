"""Free time as a balance: earned by ads while disconnected, used up only while connected (devices.py, access.py)."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.portal import auth, devices  # noqa: E402
from pqvpn.portal.access import PortalAccess  # noqa: E402
from pqvpn.portal.devices import DeviceError  # noqa: E402
from pqvpn.portal.store import Store  # noqa: E402

SERIAL = "ab" * 8


def peer(subject: str, last_rx: float) -> SimpleNamespace:
    """The few fields of a ServerNode peer that PortalAccess.sync reads (last_rx: its last packet, monotonic)."""
    cert = SimpleNamespace(serial_hex=SERIAL, addresses=["10.90.0.2/32"], key_alg=SimpleNamespace(name="ML-DSA-65"),
                           subject=subject)
    return SimpleNamespace(cert=cert, current=None, next=None, endpoint=("198.51.100.7", 4000),
                           connected_wall=time.time(), rx_bytes=0, tx_bytes=0, last_rx=last_rx)


class FreeTimeBase(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(prefix="pqvpn-free-"), "portal.db")
        self.store = Store(self.path)
        self.n = 0

    def device(self, seconds: int = 0) -> dict:
        self.n += 1
        d = self.store.create_vpn_device(f"d-{'abcdefghijklmnopqrstuvwx'[self.n] * 24}", f"h{self.n}", "android",
                                         "10.90.0.0/24", set(), "198.51.100.7")
        self.store.update_vpn_device(d["id"], active_serial=SERIAL, free_seconds=seconds)
        return self.store.vpn_device(d["id"])

    def balance(self, d: dict) -> int:
        return self.store.vpn_device(d["id"])["free_seconds"]


class TestMigration(FreeTimeBase):
    def test_time_left_on_the_old_clock_becomes_the_balance(self):
        a, b = self.device(), self.device()
        con = sqlite3.connect(self.path)
        con.execute("ALTER TABLE vpn_devices DROP COLUMN free_seconds")  # the table as it was before
        now = int(time.time())
        con.execute("UPDATE vpn_devices SET free_until = ? WHERE id = ?", (now + 900, a["id"]))
        con.execute("UPDATE vpn_devices SET free_until = ? WHERE id = ?", (now - 50, b["id"]))
        con.commit()
        con.close()
        store = Store(self.path)  # opening the file upgrades it
        self.assertAlmostEqual(store.vpn_device(a["id"])["free_seconds"], 900, delta=3)
        self.assertEqual(store.vpn_device(b["id"])["free_seconds"], 0)
        Store(self.path)  # a second open changes nothing
        self.assertAlmostEqual(store.vpn_device(a["id"])["free_seconds"], 900, delta=3)


class TestUsedOnlyWhileConnected(FreeTimeBase):
    def setUp(self):
        super().setUp()
        self.access = PortalAccess(self.path)

    def sync(self, now: float, *subjects: str, last_rx: float | None = None) -> list[str]:
        """One status interval; the listed peers' last packet came at ``last_rx`` (default: just now)."""
        return self.access.sync({s: peer(s, now if last_rx is None else last_rx) for s in subjects}, now)

    def test_charged_per_second_while_connected_and_never_while_disconnected(self):
        d = self.device(10)
        self.assertEqual(self.sync(100.0, d["subject"]), [])
        self.assertEqual(self.balance(d), 10)  # the first interval only starts the meter
        self.sync(103.0, d["subject"])
        self.assertEqual(self.balance(d), 7)
        # Disconnected: the client sends nothing more, but its session lingers on the server until it expires.
        # Found on the emulator: billing up to "now" kept charging after the tap on Disconnect.
        self.sync(106.0, d["subject"], last_rx=103.0)
        self.sync(140.0, d["subject"], last_rx=103.0)
        self.assertEqual(self.balance(d), 7)
        self.sync(500.0)  # the session expired
        self.assertEqual(self.balance(d), 7)
        self.sync(600.0, d["subject"])  # reconnects: counting starts again from here
        self.assertEqual(self.balance(d), 7)
        self.sync(602.5, d["subject"])
        self.sync(605.0, d["subject"])  # 2.5 s + 2.5 s: the half seconds are carried, not lost or doubled
        self.assertEqual(self.balance(d), 2)

    def test_idle_but_connected_is_charged_at_each_keepalive(self):
        d = self.device(100)
        self.sync(1000.0, d["subject"])
        self.sync(1010.0, d["subject"], last_rx=1000.0)  # nothing new yet: billed up to the last packet only
        self.assertEqual(self.balance(d), 100)
        self.sync(1026.0, d["subject"], last_rx=1025.0)  # the 25 s keepalive arrives: those 25 s are billed
        self.assertEqual(self.balance(d), 75)
        self.sync(1100.0, d["subject"], last_rx=1099.0)  # silent for longer than a keepalive: it had gone
        self.assertEqual(self.balance(d), 75)

    def test_reconnecting_session_is_not_charged_for_the_gap(self):
        d = self.device(50)
        self.sync(10.0, d["subject"])
        self.sync(12.0, d["subject"])  # 2 s
        self.sync(300.0, d["subject"], last_rx=300.0)  # same server session, back after 288 s off
        self.assertEqual(self.balance(d), 48)

    def test_cut_off_at_zero_and_refused_until_an_ad(self):
        d = self.device(3)
        self.sync(10.0, d["subject"])
        self.assertEqual(self.sync(14.0, d["subject"]), [d["subject"]])
        self.assertEqual(self.balance(d), 0)
        decision = devices.decide(self.store, self.store.vpn_device(d["id"]), time.time(), SERIAL)
        self.assertEqual((decision.allowed, decision.reason), (False, "free time used up: watch an ad for more"))
        self.store.add_free_seconds(d["id"], 1800)
        self.assertTrue(devices.decide(self.store, self.store.vpn_device(d["id"]), time.time(), SERIAL).allowed)

    def test_pro_devices_are_never_charged(self):
        d = self.device(0)
        with mock.patch.object(auth, "SCRYPT_N", 1 << 10):
            uid = self.store.create_user("pro", "user", "x" * 12)
        self.store.update_user(uid, plan="premium")
        self.store.update_vpn_device(d["id"], user_id=uid)
        self.sync(10.0, d["subject"])
        self.assertEqual(self.sync(20.0, d["subject"]), [])
        self.assertEqual(self.balance(d), 0)


class TestAdsOnlyWhileDisconnected(FreeTimeBase):
    def publish(self, d: dict, last_rx: int) -> None:
        self.store.publish_peers([{"username": d["subject"], "endpoint": "x", "address": "x", "suite": "",
                                   "key_alg": "", "connected_since": last_rx, "last_handshake": last_rx,
                                   "rx_bytes": 0, "tx_bytes": 0, "last_rx": last_rx}])

    def test_reward_refused_while_connected(self):
        d = self.device(0)
        settings = {**devices.APP_DEFAULTS, "admob_enabled": "1"}
        now = int(time.time())
        self.publish(d, now)
        with self.assertRaises(DeviceError) as cm:
            devices.start_reward(self.store, d, "admob", settings, now)
        self.assertEqual(cm.exception.code, "connected")
        me = devices.state(self.store, self.store.vpn_device(d["id"]), settings, now)
        self.assertTrue(me["free_counting"])
        self.publish(d, now - devices.REWARD_IDLE_SECONDS - 1)  # tapped Disconnect: silent, session not expired
        self.assertTrue(devices.start_reward(self.store, d, "admob", settings, now))
        self.assertTrue(devices.state(self.store, self.store.vpn_device(d["id"]), settings, now)["free_counting"])
        self.publish(d, now - devices.ACTIVE_SECONDS - 1)
        self.assertFalse(devices.state(self.store, self.store.vpn_device(d["id"]), settings, now)["free_counting"])
        self.store.publish_peers([])  # the session expired
        me = devices.state(self.store, self.store.vpn_device(d["id"]), settings, now)
        self.assertEqual((me["free_seconds"], me["free_counting"], me["free_until"]), (0, False, now))

    def test_a_stopped_server_does_not_count_as_connected(self):
        d = self.device(0)
        self.store.publish_peers([{"username": d["subject"], "endpoint": "x", "address": "x", "suite": "",
                                   "key_alg": "", "connected_since": 0, "last_handshake": 0, "rx_bytes": 0,
                                   "tx_bytes": 0}])
        self.assertTrue(self.store.is_connected(d["subject"], int(time.time()) - 30))
        self.assertFalse(self.store.is_connected(d["subject"], int(time.time()) + 1))  # heartbeat too old


class TestToggleAdSettings(unittest.TestCase):
    def test_modes_and_gap(self):
        self.assertEqual(devices.toggle_ads({}), "connect")  # as before: an ad after connecting
        self.assertEqual(devices.toggle_ads({"toggle_ads": "both"}), "both")
        self.assertEqual(devices.toggle_ads({"toggle_ads": "always!"}), "connect")
        self.assertEqual(devices.number({}, "toggle_ad_gap"), 0)
        self.assertEqual(devices.number({"toggle_ad_gap": "99999"}, "toggle_ad_gap"), 3600)


if __name__ == "__main__":
    unittest.main()
