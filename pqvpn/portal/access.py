"""VPN-server side of the portal: account-based access control + live status.

A client must present a certificate from the trusted CA *and* be allowed by the portal database:

  * Profiles issued by an administrator (certificate subject = username): the account must be enabled and its
    currently active profile must have that certificate's serial.  Disabling an account (or downloading a new
    profile) therefore cuts off the old credentials within one status interval -- no CRL distribution.
  * Devices enrolled by the apps (subject ``d-...``, devices.py): the device must be enabled with that serial, a
    linked account must be enabled, and a Free device must have unused free time (earned by watching ads).  Free
    time is enforced here, by the server, so a modified app cannot skip the ads.

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


class PortalAccess:
    INTERVAL = 2.0
    TOUCH_INTERVAL = 60.0      # how often connected devices' last_seen is written
    CLEANUP_INTERVAL = 3600.0  # how often anonymous devices unseen for a long time are forgotten

    def __init__(self, database: str, url: str = ""):
        self.store = Store(database)
        self.url = url
        self._last = 0.0
        self._touched = 0.0
        self._cleaned = 0.0

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
        if devices.is_device_subject(name):
            device = self.store.vpn_device_by_subject(name)
            return device is not None and devices.decide(self.store, device, now, serial).allowed
        user = self.store.user_by_name(name)
        return user is not None and bool(user["enabled"]) and (user["active_serial"] or "") == serial

    def sync(self, peers: dict, now: float) -> list[str]:
        """Publish live peers; return names of peers that must be disconnected."""
        if now - self._last < self.INTERVAL:
            return []
        self._last = now
        rows, kick = [], []
        wall = time.time()
        try:
            for name, p in peers.items():
                if not self._still_allowed(name, p.cert.serial_hex, wall):
                    kick.append(name)
                    continue
                cur = p.current or p.next
                rows.append({
                    "username": name, "endpoint": "%s:%d" % p.endpoint,
                    "address": ", ".join(p.cert.addresses), "suite": cur.suite.name if cur else "",
                    "key_alg": p.cert.key_alg.name,
                    "connected_since": int(p.connected_wall),
                    "last_handshake": int(wall - (now - cur.created)) if cur else None,
                    "rx_bytes": p.rx_bytes, "tx_bytes": p.tx_bytes})
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
        except sqlite3.Error as exc:
            log.warning("portal database: %s", exc)
            return []
        return kick
