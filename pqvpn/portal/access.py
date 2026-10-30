"""VPN-server side of the portal: account-based access control + live status.

A client must present a certificate from the trusted CA *and* be allowed by the portal database:

  * Profiles issued by an administrator (certificate subject = username): the account must be enabled and its
    currently active profile must have that certificate's serial.  Disabling an account (or downloading a new
    profile) therefore cuts off the old credentials within one status interval -- no CRL distribution.
  * Devices enrolled by the apps (subject ``d-...``, devices.py): the device must be enabled with that serial, a
    linked account must be enabled, and a Free device must have Free time left (earned by watching ads).  Free
    time is used up here, by the server, only while the device is connected: ``sync`` charges a Free device up
    to the last packet it sent (apps send a keepalive at least every 25 s).  A disconnecting client sends nothing,
    and its session lingers on the server until it expires, so billing up to "now" would charge time after the
    tap on Disconnect; a silence longer than a keepalive is never charged.  A modified app cannot skip the ads.

Accepted peers also get per-account tunnel settings pushed in the handshake (today: the DNS servers of their
plan, see plans.py).
"""

from __future__ import annotations

import logging
import sqlite3
import time

from ..handshake import HandshakeError
from ..pki import Certificate
from . import devices, plans
from .store import Store

log = logging.getLogger("pqvpn.portal")

AUDIT_RETENTION = 365 * 86400  # security log kept 12 months (public/privacy.html says so)


class PortalAccess:
    INTERVAL = 2.0
    TOUCH_INTERVAL = 60.0      # how often connected devices' last_seen is written
    CLEANUP_INTERVAL = 3600.0  # how often anonymous devices unseen for a long time are forgotten
    GAP = 40.0                 # silence longer than this (> keepalive) = it was disconnected: never charged

    def __init__(self, database: str, url: str = ""):
        self.store = Store(database)
        self.url = url
        self._last = 0.0
        self._touched = 0.0
        self._cleaned = 0.0
        # Free devices being charged: subject -> (monotonic time charged up to, unbilled fraction of a second)
        self._meter: dict[str, tuple[float, float]] = {}

    def _settings(self) -> dict:
        return self.store.settings({**plans.DEFAULT_SETTINGS, **devices.APP_DEFAULTS})

    def authorize(self, cert: Certificate) -> dict:
        """Raise HandshakeError unless the peer may connect; return its pushed-config overrides."""
        try:
            if devices.is_device_subject(cert.subject):
                return self._authorize_device(cert)
            user = self.store.user_by_name(cert.subject)
            settings = self._settings() if user else {}
        except sqlite3.Error as exc:
            raise HandshakeError(f"portal database unavailable: {exc}") from None
        if user is None:
            raise HandshakeError(f"{cert.subject}: no portal account")
        if not user["enabled"]:
            raise HandshakeError(f"{cert.subject}: account disabled in portal")
        if (user["active_serial"] or "") != cert.serial_hex:
            raise HandshakeError(f"{cert.subject}: certificate {cert.serial_hex[:8]}... superseded "
                                 "(a newer profile was downloaded)")
        dns = plans.dns_for(user, settings)
        return {"dns": dns} if dns else {}

    def _authorize_device(self, cert: Certificate) -> dict:
        device = self.store.vpn_device_by_subject(cert.subject)
        if device is None:
            raise HandshakeError(f"{cert.subject}: unknown device")
        now = time.time()
        decision = devices.decide(self.store, device, now, cert.serial_hex)
        if not decision.allowed:
            raise HandshakeError(f"{cert.subject}: {decision.reason}")
        dns = devices.pushed_dns(decision.user, self._settings(), now)
        return {"dns": dns} if dns else {}

    def _still_allowed(self, name: str, serial: str, now: float) -> bool:
        """An administrator-issued profile: the account is enabled and this is its current certificate."""
        user = self.store.user_by_name(name)
        return user is not None and bool(user["enabled"]) and (user["active_serial"] or "") == serial

    def _charge(self, name: str, last_rx: float) -> int:
        """Whole seconds a Free device used since its last charge, counted up to its last packet (monotonic)."""
        last, carry = self._meter.get(name, (last_rx, 0.0))
        if last_rx - last > self.GAP:  # it was gone (disconnected, or the network dropped): not charged
            last, carry = last_rx, 0.0
        used = max(0.0, last_rx - last) + carry
        whole = int(used)
        self._meter[name] = (max(last, last_rx), used - whole)
        return whole

    def _device_ok(self, name: str, serial: str, last_rx: float, wall: float, charges: list) -> bool:
        """Still allowed after charging this interval's Free time; Pro devices are never charged."""
        device = self.store.vpn_device_by_subject(name)
        decision = devices.decide(self.store, device, wall, serial) if device else None
        if decision is None or not decision.allowed:
            return False
        if decision.plan != "free":
            self._meter.pop(name, None)  # a device that turns Free again starts a fresh meter
            return True
        used = self._charge(name, last_rx)
        if used:
            charges.append((name, used))
        return device["free_seconds"] - used > 0

    def sync(self, peers: dict, now: float) -> list[str]:
        """Publish live peers, charge connected Free devices; return names of peers that must be disconnected."""
        if now - self._last < self.INTERVAL:
            return []
        self._last = now
        rows, kick, charges = [], [], []
        wall = time.time()
        try:
            for name, p in peers.items():
                last_rx = min(p.last_rx or now, now)
                ok = (self._device_ok(name, p.cert.serial_hex, last_rx, wall, charges)
                      if devices.is_device_subject(name) else self._still_allowed(name, p.cert.serial_hex, wall))
                if not ok:
                    kick.append(name)
                    self._meter.pop(name, None)
                    continue
                cur = p.current or p.next
                rows.append({
                    "username": name, "endpoint": "%s:%d" % p.endpoint,
                    "address": ", ".join(p.cert.addresses), "suite": cur.suite.name if cur else "",
                    "key_alg": p.cert.key_alg.name,
                    "connected_since": int(p.connected_wall),
                    "last_handshake": int(wall - (now - cur.created)) if cur else None,
                    "rx_bytes": p.rx_bytes, "tx_bytes": p.tx_bytes,
                    "last_rx": int(wall - (now - p.last_rx)) if p.last_rx else None})
            self.store.charge_free_seconds(charges)
            for gone in set(self._meter) - set(peers):  # disconnected: their time stops here
                del self._meter[gone]
            self.store.publish_peers(rows)
            if now - self._touched >= self.TOUCH_INTERVAL:
                self._touched = now
                self.store.touch_vpn_devices([r["username"] for r in rows
                                              if devices.is_device_subject(r["username"])], int(wall))
            if now - self._cleaned >= self.CLEANUP_INTERVAL:
                self._cleaned = now
                days = devices.number(self._settings(), "device_cleanup_days")
                if (n := self.store.purge_anonymous_devices(days * 86400)):
                    log.info("forgot %d anonymous device(s) unseen for %d days", n, days)
                self.store.purge_rewards(7 * 86400)
                self.store.purge_audit(AUDIT_RETENTION)
        except sqlite3.Error as exc:
            log.warning("portal database: %s", exc)
            return []
        return kick
