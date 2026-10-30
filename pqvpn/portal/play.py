"""Pro bought inside the Android app from Google Play (Google Play Billing), checked by the portal with Google's API.

Google Play's payments policy requires Play Billing for subscriptions sold inside an app installed from Google Play,
so the Play build of the app sells Pro through Google; the website and the Windows app keep Paddle (payments.py).
The model mirrors payments.py -- the app never decides on its own:

  1. In Play Console the admin creates one subscription (product id, default ``shieldsvpn_pro``) with weekly / monthly
     / yearly base plans and their prices, and gives a Google Cloud service account access to the Play Developer API.
  2. The signed-in app buys a base plan with ``BillingFlowParams.setObfuscatedAccountId(account_ref)``: an HMAC of
     the account id that only the portal can compute, so a purchase cannot be claimed by another account.
  3. The app sends the purchase token to ``/api/v1/play/verify``.  The portal asks Google
     (``purchases.subscriptionsv2.get``): our product, the same account reference, and a paid state (active, in grace,
     or canceled but not yet expired) -> plan = premium until ``expiryTime`` + 1 day.  The portal acknowledges the
     purchase itself (Google refunds purchases left unacknowledged for 3 days).  A token belongs to one account.
  4. A background reconcile re-checks tokens close to their end (renewals, cancellations), as payments.py does, and
     the app re-sends its active purchases when it starts (restore).

Network access goes only to Google's fixed hosts.  The service-account key is a file next to the database (mode 0600,
like the Firebase key); purchase tokens are never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import threading
import time
import urllib.parse

from . import firebase
from .google import TOKEN_URI, GoogleError, ServiceAccount
from .payments import GRACE, iso_to_epoch
from .store import Store

log = logging.getLogger("pqvpn.portal")

API = "https://androidpublisher.googleapis.com/androidpublisher/v3"
SCOPE = "https://www.googleapis.com/auth/androidpublisher"
KEY_FILE = "play-key.json"
DEFAULT_SETTINGS = {"play_enabled": "0", "play_package": "com.shieldsvpn.vpn", "play_product_id": "shieldsvpn_pro"}
PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
PRODUCT_RE = re.compile(r"^[a-z0-9][a-z0-9._]{0,39}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]{20,2048}$")  # Google sets no documented maximum; tokens are ~150-200
# SUBSCRIPTION_STATE_CANCELED: auto-renew is off but the paid period has not ended yet.
PAID_STATES = {"SUBSCRIPTION_STATE_ACTIVE", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD", "SUBSCRIPTION_STATE_CANCELED"}
ACK_STATES = {"SUBSCRIPTION_STATE_ACTIVE", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"}
FINAL_STATES = {"SUBSCRIPTION_STATE_EXPIRED", "SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED"}


class PlayError(Exception):
    """A refused Play purchase: same shape as payments.PaymentError, so the app API reports it the same way."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class PlayClient(ServiceAccount):
    """The two Play Developer API calls the portal needs, with the service-account login of google.py."""

    def __init__(self, key: dict, api: str = API, timeout: float = 20, token_uri: str = TOKEN_URI):
        super().__init__(key, SCOPE, timeout, token_uri)
        self.api = api.rstrip("/")  # api only for tests (a fake Google on loopback)

    def subscription(self, package: str, token: str) -> dict:
        return self._api("GET", f"{self.api}/applications/{package}/purchases/subscriptionsv2/tokens/"
                                f"{urllib.parse.quote(token, safe='')}")

    def acknowledge(self, package: str, product_id: str, token: str) -> None:
        self._api("POST", f"{self.api}/applications/{package}/purchases/subscriptions/{product_id}/tokens/"
                          f"{urllib.parse.quote(token, safe='')}:acknowledge", {})


def account_ref(secret: bytes, user_id: int) -> str:
    """The obfuscated account id the app passes to Google: HMAC-SHA256 of the account id, 32 hex digits."""
    return hmac.new(secret, f"play-account:{user_id}".encode(), hashlib.sha256).hexdigest()[:32]


class PlayBilling:
    """Verification of Play purchase tokens and the periodic reconcile.  Thread-safe."""

    RECONCILE_EVERY = 6 * 3600

    def __init__(self, store: Store, settings_fn, key_path: str, ref_secret: bytes, client_factory=None):
        self.store, self.settings, self.key_path, self.ref_secret = store, settings_fn, key_path, ref_secret
        self.client_factory = client_factory or (lambda key: PlayClient(key))
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.last_error = ""

    # -------------------------------------------------------------- configuration
    def key(self) -> dict | None:
        try:
            return firebase.load_key(self.key_path)
        except firebase.FirebaseError:
            return None

    def ready(self, settings: dict | None = None) -> bool:
        """Play billing is switched on and configured (key, package name, product id)."""
        s = settings or self.settings()
        return (s.get("play_enabled") == "1" and bool(PACKAGE_RE.match(s.get("play_package", "")))
                and bool(PRODUCT_RE.match(s.get("play_product_id", ""))) and self.key() is not None)

    def ref(self, user_id: int) -> str:
        return account_ref(self.ref_secret, user_id)

    def client(self) -> PlayClient:
        key = self.key()
        if key is None or not self.ready():
            raise PlayError(404, "disabled", "Google Play purchases are not available")
        return self.client_factory(key)

    # -------------------------------------------------------------- verification
    def verify(self, user: dict, product_id: str, token: str) -> str:
        """Check one purchase with Google and apply it to ``user``.  Returns Google's subscription state."""
        s = self.settings()
        if not TOKEN_RE.match(token or ""):
            raise PlayError(400, "bad_token", "that is not a Google Play purchase token")
        if product_id != s.get("play_product_id"):
            raise PlayError(400, "bad_product", "that is not the ShieldsVPN Pro subscription")
        with self.lock:
            known = self.store.play_purchase(token)
            if known is not None and known["user_id"] != user["id"]:
                raise PlayError(409, "token_in_use", "this purchase belongs to another account")
            return self._check(self.client(), s, user["id"], token)

    def _check(self, client: PlayClient, s: dict, user_id: int, token: str) -> str:
        package, product = s["play_package"], s["play_product_id"]
        try:
            sub = client.subscription(package, token)
        except GoogleError as exc:
            self.last_error = str(exc)
            raise PlayError(502, "google", f"Google Play did not confirm the purchase ({exc})") from None
        items = [i for i in sub.get("lineItems") or [] if isinstance(i, dict) and i.get("productId") == product]
        if not items:
            raise PlayError(400, "bad_product", "that purchase is not the ShieldsVPN Pro subscription")
        ref = ((sub.get("externalAccountIdentifiers") or {}).get("obfuscatedExternalAccountId") or "")
        if not hmac.compare_digest(ref, self.ref(user_id)):
            raise PlayError(403, "wrong_account", "this purchase was made for another account")
        state = str(sub.get("subscriptionState", ""))
        try:
            expires = max(iso_to_epoch(i.get("expiryTime", "")) for i in items)
        except ValueError:
            raise PlayError(502, "google", "Google Play sent no end date for the subscription") from None
        base_plan = str((items[0].get("offerDetails") or {}).get("basePlanId", ""))[:40]
        test = "testPurchase" in sub
        self.store.save_play_purchase(token, user_id, product, base_plan, state, expires, test)
        linked = sub.get("linkedPurchaseToken")
        if isinstance(linked, str) and linked != token:
            self.store.replace_play_purchase(linked, user_id)  # an upgrade / downgrade / re-signup replaced it
        if state in ACK_STATES and sub.get("acknowledgementState") == "ACKNOWLEDGEMENT_STATE_PENDING":
            try:
                client.acknowledge(package, product, token)
            except GoogleError as exc:  # the next check retries; Google allows 3 days
                log.warning("could not acknowledge a Google Play purchase: %s", exc)
        if state in PAID_STATES and expires > time.time():
            self._grant(user_id, expires + GRACE, state, base_plan, test)
        return state

    def _grant(self, user_id: int, until: int, state: str, base_plan: str, test: bool) -> bool:
        """Premium until ``until``, never shortening a longer paid period or an admin's open-ended Premium."""
        user = self.store.user(user_id)
        if user is None:
            return False
        if user["plan"] == "premium" and user["plan_expires"] is None:
            return False
        current = (user["plan_expires"] or 0) if user["plan"] == "premium" else 0
        if until <= current:
            return False
        self.store.update_user(user_id, plan="premium", plan_expires=until)
        self.store.audit("plan_paid", actor=user["username"],
                         detail=f"Google Play {base_plan or 'subscription'} {state.rsplit('_', 1)[-1].lower()}"
                                f"{' (test purchase)' if test else ''} until "
                                f"{time.strftime('%Y-%m-%d', time.gmtime(until))}")
        return True

    # -------------------------------------------------------------- reconcile
    def reconcile_all(self) -> int:
        """Re-check purchases whose paid period ends within two days (renewals and cancellations)."""
        if not self.ready():
            return 0
        s, n = self.settings(), 0
        client = self.client()
        for row in self.store.play_purchases_due(time.time() + GRACE + 2 * 86400):
            with self.lock:
                try:
                    self._check(client, s, row["user_id"], row["token"])
                    n += 1
                except PlayError as exc:
                    log.warning("Google Play reconcile: %s", exc.message)
        return n

    def start(self) -> None:
        def loop():
            while not self._stop.wait(60):
                try:
                    self.reconcile_all()
                except Exception:  # noqa: BLE001 -- keep the loop alive; the next run retries
                    log.exception("Google Play reconcile failed")
                self._stop.wait(self.RECONCILE_EVERY)
        threading.Thread(target=loop, name="portal-play", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
