"""Verification of rewarded-ad callbacks.

Google AdMob server-side verification (SSV), as documented at
https://developers.google.com/admob/android/ssv: after a user finishes a rewarded ad, Google calls the
configured URL with a query string ending in ``&signature=...&key_id=...``.  The signature is ECDSA P-256 /
SHA-256 (DER, base64url) over the query string *up to* the ``&signature=`` parameter, made with one of the keys
Google publishes at ``VERIFIER_KEYS_URL``.  The app passes our one-time reward nonce as ``custom_data``, and
``transaction_id`` makes each callback single use (devices.grant / store.claim_reward).

The keys are fetched only from the fixed Google URL (never a URL taken from a request) and checked with
OpenSSL (ossl.verify_hashed); no cryptography is implemented here.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
import urllib.parse
import urllib.request

from ..crypto import ossl

log = logging.getLogger("pqvpn.portal")

VERIFIER_KEYS_URL = "https://www.gstatic.com/admob/reward/verifier-keys.json"
MAX_AGE = 3600          # a callback older than one hour is refused
KEY_CACHE_SECONDS = 24 * 3600
REFETCH_AFTER = 300     # an unknown key id triggers at most one refetch per five minutes


class SsvError(Exception):
    pass


def _fetch_keys(timeout: float = 10) -> bytes:
    with urllib.request.urlopen(VERIFIER_KEYS_URL, timeout=timeout) as r:  # noqa: S310 -- fixed https URL
        return r.read(256 * 1024)


class AdMobVerifier:
    def __init__(self, fetch=_fetch_keys):
        self.fetch = fetch  # tests swap in a fake that serves their own key
        self.keys: dict[str, ossl.PKey] = {}
        self.fetched_at = 0.0
        self.lock = threading.Lock()

    def _load(self, now: float) -> None:
        data = json.loads(self.fetch())
        keys = {}
        for k in data.get("keys", []):
            pem = k.get("pem", "")
            if isinstance(pem, str) and pem.startswith("-----BEGIN PUBLIC KEY-----"):
                keys[str(k.get("keyId"))] = ossl.public_from_pem(pem.encode("ascii"))
        if not keys:
            raise SsvError("Google published no verifier keys")
        self.keys, self.fetched_at = keys, now

    def key(self, key_id: str, now: float) -> ossl.PKey:
        with self.lock:
            stale = now - self.fetched_at > KEY_CACHE_SECONDS
            if stale or (key_id not in self.keys and now - self.fetched_at > REFETCH_AFTER):
                try:
                    self._load(now)
                except Exception as exc:  # noqa: BLE001 -- network/JSON problems: keep the cached keys
                    log.warning("AdMob verifier keys: %s", exc)
            if key_id not in self.keys:
                raise SsvError(f"unknown AdMob key id {key_id!r}")
            return self.keys[key_id]

    def verify(self, raw_query: str, now: float | None = None) -> dict:
        """Check a callback's signature and age; return its parameters (custom_data, transaction_id, ...)."""
        now = time.time() if now is None else now
        marker = raw_query.find("&signature=")
        if marker <= 0:
            raise SsvError("missing signature")
        # Only the signed part carries parameters; after it Google sends exactly signature and key_id.  Anything
        # else there (e.g. a second custom_data appended by whoever relays the URL) is refused, not just ignored.
        params = {k: v[0] for k, v in urllib.parse.parse_qs(raw_query[:marker], keep_blank_values=True).items()}
        tail = urllib.parse.parse_qs(raw_query[marker + 1:], keep_blank_values=True)
        if set(tail) != {"signature", "key_id"} or any(len(v) != 1 for v in tail.values()):
            raise SsvError("unexpected parameters after the signature")
        sig_b64, key_id = tail["signature"][0], tail["key_id"][0]
        if not sig_b64 or not key_id:
            raise SsvError("missing signature or key id")
        try:
            sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        except ValueError:
            raise SsvError("malformed signature") from None
        if not ossl.verify_hashed(self.key(key_id, now), raw_query[:marker].encode("utf-8"), sig, "SHA256"):
            raise SsvError("bad signature")
        try:
            ts = int(params.get("timestamp", "0")) / 1000  # milliseconds
        except ValueError:
            raise SsvError("bad timestamp") from None
        if not now - MAX_AGE <= ts <= now + 300:
            raise SsvError("callback too old")
        if not params.get("transaction_id") or not params.get("custom_data"):
            raise SsvError("missing transaction id or custom data")
        return params
