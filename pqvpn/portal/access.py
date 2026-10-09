"""VPN-server side of the portal: account-based access control + live status.

A client must present a certificate from the trusted CA *and* belong to an
enabled portal account whose currently active profile has that certificate's
serial.  Disabling an account (or downloading a new profile) therefore cuts
off the old credentials within one status interval -- no CRL distribution.

Accepted accounts also get per-account tunnel settings pushed in the handshake
(today: the DNS servers of their plan, see plans.py).
"""

from __future__ import annotations

import logging
import sqlite3
import time

from ..handshake import HandshakeError
from ..pki import Certificate
from . import plans
from .store import Store

log = logging.getLogger("pqvpn.portal")


class PortalAccess:
    INTERVAL = 2.0

    def __init__(self, database: str, url: str = ""):
        self.store = Store(database)
        self.url = url
        self._last = 0.0

    def authorize(self, cert: Certificate) -> dict:
        """Raise HandshakeError unless the account may connect; return its pushed-config overrides."""
        try:
            user = self.store.user_by_name(cert.subject)
            settings = self.store.settings(plans.DEFAULT_SETTINGS) if user else {}
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

    def sync(self, peers: dict, now: float) -> list[str]:
        """Publish live peers; return names of peers that must be disconnected."""
        if now - self._last < self.INTERVAL:
            return []
        self._last = now
        rows, kick = [], []
        wall = time.time()
        try:
            for name, p in peers.items():
                user = self.store.user_by_name(name)
                if user is None or not user["enabled"] or (user["active_serial"] or "") != p.cert.serial_hex:
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
        except sqlite3.Error as exc:
            log.warning("portal database: %s", exc)
            return []
        return kick
