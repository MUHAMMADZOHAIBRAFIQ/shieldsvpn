"""Pro subscriptions through Paddle Billing (merchant of record: Paddle takes the card, handles tax and receipts).

No card data ever reaches the portal.  The flow (docs/SPEC.md "Payments"):

  0. The admin sets the weekly / monthly / yearly amounts in Settings; the portal creates the matching recurring
     prices at Paddle (``sync_prices``).  A changed amount gets a new price and the old one is archived, so
     existing subscribers keep the price they signed up for.
  1. The app (signed in) asks for a checkout of one of those plans.  The portal creates the Paddle *transaction*
     itself, through the API, with that plan's price and ``custom_data.shieldsvpn_user`` = the account id, and
     hands the app a one-time ``/pay/<code>`` link.  So the buyer cannot change what is bought or for whom.
  2. ``/pay/<code>`` loads Paddle.js and opens Paddle's checkout for that transaction.
  3. Pro is switched on only from data the portal fetched from Paddle's API itself (``reconcile``): the
     transaction is paid/completed, belongs to this account, is for the configured price, and its subscription
     is active; ``plan_expires`` = the end of the paid billing period (+ a day of grace).  This *pull* works
     even when Paddle cannot reach the portal (testing through playit.gg).
  4. With a public HTTPS address, Paddle's webhooks speed this up: the ``Paddle-Signature`` HMAC-SHA256 is
     verified (with a 5-minute replay window) and the event only triggers the same API fetch -- the body is
     never trusted on its own.
  5. Renewals, cancellations and refunds are picked up by the periodic reconcile (and by webhooks).

Network access goes only to Paddle's fixed API hosts (no URL comes from a request, so no SSRF).  The API key
and the webhook secret are stored sealed with the portal vault and never logged.
"""

from __future__ import annotations

import calendar
import decimal
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from .store import Store

log = logging.getLogger("pqvpn.portal")

API_HOSTS = {"sandbox": "https://sandbox-api.paddle.com", "live": "https://api.paddle.com"}
PAY_LINK_TTL = 30 * 60
MAX_OPEN_CHECKOUTS = 5         # unfinished checkouts per account per hour (each one is a Paddle transaction)
GRACE = 86400                  # Pro stays on one day past the billing period, so a renewal has time to land
WEBHOOK_TOLERANCE = 300
PAID_STATUSES = {"paid", "completed"}
ACTIVE_SUBSCRIPTION = {"active", "trialing", "past_due"}  # past_due: Paddle is still retrying the card
SECRET_SETTINGS = ("paddle_api_key", "paddle_webhook_secret")
# Pro plans: key = Paddle's billing interval, value = the name people see.
PERIODS = {"week": "Weekly", "month": "Monthly", "year": "Yearly"}
# Currencies the admin can choose, with their decimal places (Paddle takes amounts in the smallest unit).
CURRENCIES = {"USD": 2, "EUR": 2, "GBP": 2, "AUD": 2, "CAD": 2, "CHF": 2, "INR": 2, "JPY": 0}
PRICE_HISTORY = 50             # replaced prices still accepted for checkouts started before the change
# pro_price_<period>: the amount the admin set ("" = not sold); paddle_price_<period>: the Paddle price the portal
# created for it; paddle_price_history: every price the portal created (comma-separated).
DEFAULT_SETTINGS = {"payments_enabled": "0", "paddle_env": "sandbox", "paddle_api_key": "", "paddle_client_token": "",
                    "paddle_product_id": "", "pro_currency": "USD", "paddle_webhook_secret": "",
                    "paddle_price_history": "", **{f"pro_price_{p}": "" for p in PERIODS},
                    **{f"paddle_price_{p}": "" for p in PERIODS}}
PRICE_ID_RE = re.compile(r"^pri_[a-z0-9]{10,64}$")
PRODUCT_ID_RE = re.compile(r"^pro_[a-z0-9]{10,64}$")
CLIENT_TOKEN_RE = re.compile(r"^(test|live)_[A-Za-z0-9]{10,64}$")
AMOUNT_RE = re.compile(r"^\d{1,7}(\.\d{1,2})?$")


class PaymentError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def ready(settings: dict) -> bool:
    """Payments are switched on and fully configured, with at least one Pro plan on sale."""
    return (settings.get("payments_enabled") == "1" and bool(settings.get("paddle_api_key"))
            and bool(CLIENT_TOKEN_RE.match(settings.get("paddle_client_token", ""))) and bool(offers(settings)))


def normalize_amount(text: str, currency: str) -> str:
    """'4.9' -> '4.90' for USD; '' (plan not sold) stays ''.  Raises ValueError with a reason for the admin."""
    text = text.strip()
    if not text:
        return ""
    if not AMOUNT_RE.match(text):
        raise ValueError("enter an amount like 4.99")
    digits, value = CURRENCIES[currency], decimal.Decimal(text)
    if value <= 0:
        raise ValueError("must be more than 0")
    if value != value.quantize(decimal.Decimal(1).scaleb(-digits)):
        raise ValueError(f"{currency} has no decimal places" if digits == 0 else
                         f"{currency} has {digits} decimal places")
    return f"{value:.{digits}f}"


def to_minor(amount: str, currency: str) -> str:
    """'4.99' USD -> '499': Paddle wants the smallest currency unit as an integer string."""
    return str(int(decimal.Decimal(amount).scaleb(CURRENCIES[currency])))


def offers(settings: dict) -> list[dict]:
    """The Pro plans on sale (an amount set and its Paddle price created), weekly first.  Display data only: the
    apps and the web page never see Paddle ids."""
    currency = settings.get("pro_currency", "USD")
    out = []
    for period, name in PERIODS.items():
        amount = settings.get(f"pro_price_{period}", "")
        if amount and PRICE_ID_RE.match(settings.get(f"paddle_price_{period}", "")):
            out.append({"period": period, "name": name, "amount": amount, "currency": currency,
                        "label": f"{currency} {amount} / {period}"})
    return out


def default_period(settings: dict) -> str:
    """What a checkout without a choice buys (older app builds): monthly if it is on sale, else the first plan."""
    periods = [o["period"] for o in offers(settings)]
    return "month" if "month" in periods else (periods[0] if periods else "")


def known_prices(settings: dict) -> set[str]:
    """Every Paddle price the portal sold Pro with: the current ones, replaced ones (a checkout started before an
    amount changed still counts) and the single price of older portal versions."""
    ids = {settings.get(f"paddle_price_{p}", "") for p in PERIODS} | {settings.get("paddle_price_id", "")}
    ids |= set(settings.get("paddle_price_history", "").split(","))
    return {i for i in ids if PRICE_ID_RE.match(i)}


def sync_prices(paddle: "PaddleClient", old: dict, new: dict) -> tuple[dict, list[str]]:
    """Create the Paddle prices that ``new`` settings need.  Returns (price settings to store, old price ids to
    archive once those are stored).  Raises PaymentError, after archiving what it created, so a failed save
    leaves nothing new on sale.

    Prices are never edited at Paddle: a new amount, currency, product or environment gets a new price and the old
    one is archived, so existing subscriptions keep the price they were bought at.
    """
    same_place = all(new.get(k) == old.get(k) for k in ("paddle_env", "paddle_product_id", "pro_currency"))
    store, archive, created = {}, [], []
    try:
        for period, name in PERIODS.items():
            key, amount = f"paddle_price_{period}", new.get(f"pro_price_{period}", "")
            current = old.get(key, "")
            if amount and current and same_place and amount == old.get(f"pro_price_{period}"):
                store[key] = current
                continue
            store[key] = ""
            if amount:
                if not new.get("paddle_api_key"):
                    raise PaymentError(400, "config", "enter the Paddle API key first")
                if not PRODUCT_ID_RE.match(new.get("paddle_product_id", "")):
                    raise PaymentError(400, "config", "enter the Paddle product ID (pro_...) first")
                store[key] = paddle.create_price(new["paddle_product_id"], period,
                                                 to_minor(amount, new["pro_currency"]), new["pro_currency"],
                                                 f"ShieldsVPN Pro, {name.lower()}")
                created.append(store[key])
            if current:
                archive.append(current)
    except PaymentError:
        for price_id in created:
            try:
                paddle.archive_price(price_id)
            except PaymentError as exc:
                log.warning("could not archive Paddle price %s after a failed save: %s", price_id, exc.message)
        raise
    history = [p for p in old.get("paddle_price_history", "").split(",") if p] + created
    store["paddle_price_history"] = ",".join(list(dict.fromkeys(history))[-PRICE_HISTORY:])
    if old.get("paddle_env") != new.get("paddle_env"):
        archive = []  # the old prices live in the other Paddle environment
    return store, archive


def iso_to_epoch(value: str) -> int:
    """'2026-11-22T10:00:00.123456Z' -> Unix seconds (Paddle sends RFC 3339 UTC timestamps)."""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", value or "")
    if not m:
        raise ValueError(f"bad timestamp {value!r}")
    return calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))


# ------------------------------------------------------------------ Paddle API

class PaddleClient:
    def __init__(self, env: str, api_key: str, timeout: float = 20, base_url: str | None = None):
        if env not in API_HOSTS:
            raise PaymentError(500, "config", "Paddle environment must be sandbox or live")
        self.base = base_url or API_HOSTS[env]  # base_url only for tests (a fake Paddle on loopback)
        self.api_key, self.timeout = api_key, timeout

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
            "Accept": "application/json", "Paddle-Version": "1", "User-Agent": "ShieldsVPN-portal"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 -- fixed Paddle host
                out = json.loads(r.read(4 << 20) or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read(65536)).get("error", {})
            except ValueError:
                detail = {}
            raise PaymentError(502, "paddle", f"Paddle refused the request ({exc.code}: "
                                              f"{detail.get('code', '')} {detail.get('detail', '')})".strip()) from None
        except (OSError, ValueError) as exc:
            raise PaymentError(502, "paddle_unreachable", f"cannot reach Paddle ({exc.__class__.__name__})") from None
        if not isinstance(out, dict) or not isinstance(out.get("data"), (dict, list)):
            raise PaymentError(502, "paddle", "unexpected answer from Paddle")
        return out["data"]

    def customer_for(self, email: str) -> str:
        found = self.request("GET", "/customers?email=" + urllib.request.quote(email))
        if isinstance(found, list) and found:
            return found[0]["id"]
        return self.request("POST", "/customers", {"email": email})["id"]

    def create_transaction(self, price_id: str, customer_id: str, user_id: int) -> dict:
        return self.request("POST", "/transactions", {
            "items": [{"price_id": price_id, "quantity": 1}], "customer_id": customer_id,
            "custom_data": {"shieldsvpn_user": str(user_id)}})

    def create_price(self, product_id: str, period: str, amount_minor: str, currency: str, description: str) -> str:
        """A recurring price (one per billing period) for the Pro product; returns its id."""
        out = self.request("POST", "/prices", {
            "product_id": _safe_id(product_id, "pro"), "description": description, "name": PERIODS[period],
            "billing_cycle": {"interval": period, "frequency": 1},
            "unit_price": {"amount": amount_minor, "currency_code": currency},
            "quantity": {"minimum": 1, "maximum": 1}})
        return _safe_id(str(out.get("id", "")) if isinstance(out, dict) else "", "pri")

    def archive_price(self, price_id: str) -> None:
        """Take a price off sale.  Subscriptions already on it keep renewing at that price."""
        self.request("PATCH", f"/prices/{_safe_id(price_id, 'pri')}", {"status": "archived"})

    def transaction(self, txn_id: str) -> dict:
        return self.request("GET", f"/transactions/{_safe_id(txn_id, 'txn')}")

    def subscription(self, sub_id: str) -> dict:
        return self.request("GET", f"/subscriptions/{_safe_id(sub_id, 'sub')}")

    def portal_session(self, customer_id: str, subscription_id: str | None) -> str:
        body = {"subscription_ids": [subscription_id]} if subscription_id else {}
        out = self.request("POST", f"/customers/{_safe_id(customer_id, 'ctm')}/portal-sessions", body)
        return out.get("urls", {}).get("general", {}).get("overview", "")


def _safe_id(value: str, prefix: str) -> str:
    if not re.fullmatch(prefix + r"_[a-z0-9]{10,64}", value or ""):
        raise PaymentError(400, "bad_id", f"not a Paddle {prefix} id")
    return value


# ------------------------------------------------------------------ the portal side

class Payments:
    """Checkout links, verification against Paddle's API, and the periodic reconcile.  Thread-safe."""

    RECONCILE_EVERY = 6 * 3600

    def __init__(self, store: Store, settings_fn, client_factory=None):
        self.store = store
        self.settings = settings_fn  # Portal.settings (secrets already unsealed)
        self.client_factory = client_factory or (lambda s: PaddleClient(s["paddle_env"], s["paddle_api_key"]))
        self.lock = threading.Lock()
        self._stop = threading.Event()

    def client(self) -> PaddleClient:
        s = self.settings()
        if not ready(s):
            raise PaymentError(404, "disabled", "payments are not available yet")
        return self.client_factory(s)

    # -------------------------------------------------------------- checkout
    def checkout(self, user: dict, period: str) -> str:
        """Create the Paddle transaction for this account's chosen Pro plan; return a one-time pay-link code."""
        if not user.get("email") or not user.get("email_verified"):
            raise PaymentError(409, "email_required", "verify your email address first")
        s = self.settings()
        paddle = self.client()
        if period not in [o["period"] for o in offers(s)]:
            raise PaymentError(400, "bad_period", "that Pro plan is not on sale")
        customer = user.get("paddle_customer_id") or paddle.customer_for(user["email"])
        if customer != user.get("paddle_customer_id"):
            self.store.update_user(user["id"], paddle_customer_id=customer)
        txn = paddle.create_transaction(s[f"paddle_price_{period}"], customer, user["id"])
        code = secrets.token_urlsafe(24)
        self.store.create_pay_link(_hash(code), user["id"], _safe_id(txn["id"], "txn"), PAY_LINK_TTL)
        return code

    def pay_link(self, code: str) -> dict | None:
        link = self.store.pay_link(_hash(code))
        if link is None or link["expires_at"] < time.time():
            return None
        return link

    # -------------------------------------------------------------- verification (pull)
    def reconcile_user(self, user_id: int) -> bool:
        """Check this account's recent checkouts and its subscription with Paddle; True if the plan changed."""
        with self.lock:
            try:
                paddle = self.client()
            except PaymentError:
                return False
            changed = False
            for link in self.store.open_pay_links(user_id, time.time() - 86400):
                try:
                    txn = paddle.transaction(link["txn_id"])
                except PaymentError as exc:
                    log.warning("payment check failed: %s", exc.message)
                    continue
                if txn.get("status") in PAID_STATUSES:
                    self.store.complete_pay_link(link["code_hash"])
                    changed |= self._apply_transaction(paddle, txn, user_id)
            user = self.store.user(user_id)
            if user and user.get("paddle_subscription_id"):
                changed |= self._apply_subscription(paddle, user["paddle_subscription_id"], user_id)
            return changed

    def _apply_transaction(self, paddle: PaddleClient, txn: dict, user_id: int) -> bool:
        s = self.settings()
        owner = str((txn.get("custom_data") or {}).get("shieldsvpn_user", ""))
        prices = {(i.get("price") or {}).get("id") or i.get("price_id") for i in txn.get("items") or []}
        if owner != str(user_id) or not prices or not prices <= known_prices(s):
            log.warning("ignoring Paddle transaction %s: not this account's Pro purchase", txn.get("id"))
            return False
        totals = (txn.get("details") or {}).get("totals") or {}
        self.store.record_payment("paddle", txn["id"], user_id, txn.get("status", ""),
                                  str(totals.get("grand_total", "")), str(txn.get("currency_code", "")))
        sub_id = txn.get("subscription_id")
        if sub_id:
            self.store.update_user(user_id, paddle_subscription_id=_safe_id(sub_id, "sub"))
            return self._apply_subscription(paddle, sub_id, user_id)
        return False

    def _apply_subscription(self, paddle: PaddleClient, sub_id: str, user_id: int) -> bool:
        try:
            sub = paddle.subscription(sub_id)
        except PaymentError as exc:
            log.warning("subscription check failed: %s", exc.message)
            return False
        if str((sub.get("custom_data") or {}).get("shieldsvpn_user", user_id)) != str(user_id):
            return False
        user = self.store.user(user_id)
        if user is None:
            return False
        period = sub.get("current_billing_period") or {}
        if sub.get("status") in ACTIVE_SUBSCRIPTION and period.get("ends_at"):
            until = iso_to_epoch(period["ends_at"]) + GRACE
        elif sub.get("status") == "canceled" and sub.get("canceled_at"):
            # Never later than an end date already granted.  An account with none yet (cancelled before the first
            # check) still gets one: plan_expires = 0 would mean "no end date" (plans.effective_plan).
            until = iso_to_epoch(sub["canceled_at"]) + GRACE
            if user["plan_expires"]:
                until = min(until, user["plan_expires"])
        else:
            return False
        if user["plan"] == "premium" and user["plan_expires"] == until:
            return False
        self.store.update_user(user_id, plan="premium", plan_expires=until)
        self.store.audit("plan_paid", actor=user["username"],
                         detail=f"Paddle subscription {sub.get('status')} until {time.strftime('%Y-%m-%d', time.gmtime(until))}")
        return True

    def reconcile_all(self) -> int:
        """Renewals and cancellations: subscriptions whose paid period ends within two days (plan_expires also
        holds the day of grace, hence GRACE + 2 days)."""
        n = 0
        for user in self.store.users_with_subscriptions(time.time() + GRACE + 2 * 86400):
            n += self.reconcile_user(user["id"])
        return n

    def start(self) -> None:
        def loop():
            while not self._stop.wait(60):
                if ready(self.settings()):
                    try:
                        self.reconcile_all()
                    except Exception:  # noqa: BLE001 -- keep the loop alive; the next run retries
                        log.exception("payment reconcile failed")
                    self._stop.wait(self.RECONCILE_EVERY)
        threading.Thread(target=loop, name="portal-payments", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    # -------------------------------------------------------------- webhooks (push)
    def webhook(self, raw: bytes, signature_header: str, now: float | None = None) -> None:
        """Verify Paddle's signature, then re-check the account it names through the API."""
        secret = self.settings().get("paddle_webhook_secret", "")
        if not secret:
            raise PaymentError(404, "disabled", "webhooks are not configured")
        if not verify_signature(raw, signature_header, secret, time.time() if now is None else now):
            raise PaymentError(401, "bad_signature", "signature check failed")
        try:
            event = json.loads(raw)
            data = event["data"]
            user_id = int((data.get("custom_data") or {}).get("shieldsvpn_user", ""))
        except (ValueError, KeyError, TypeError, AttributeError):
            return  # a well-signed event about something else (not one of our purchases)
        if data.get("id", "").startswith("sub_") and self.store.user(user_id):
            self.store.update_user(user_id, paddle_subscription_id=_safe_id(data["id"], "sub"))
        self.reconcile_user(user_id)


def verify_signature(raw: bytes, header: str, secret: str, now: float) -> bool:
    """Paddle-Signature: "ts=<unix>;h1=<hex HMAC-SHA256(secret, ts + ':' + raw body)>"."""
    parts = dict(p.split("=", 1) for p in (header or "").split(";") if "=" in p)
    try:
        ts = int(parts.get("ts", ""))
    except ValueError:
        return False
    if abs(now - ts) > WEBHOOK_TOLERANCE:
        return False
    expected = hmac.new(secret.encode(), f"{ts}:".encode() + raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("h1", ""))


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()
