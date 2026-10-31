"""JSON API for the ShieldsVPN apps (Android, Windows): enrollment, account sign-in and free time from ads.

Security model (OWASP REST Security Cheat Sheet, OWASP API Security Top 10):

  * Authentication: one 256-bit bearer token per enrolled device (``Authorization: Bearer ...``), stored only as
    a SHA-256 hash (devices.py).  The portal's session cookie is never read here, so a browser cannot be made to
    send authenticated API calls (no CSRF surface).  Cross-site ``Origin`` headers are refused anyway, and bodies
    must be ``application/json``, which a cross-site page cannot send without a CORS preflight this API never
    approves.
  * The Host allow-list (DNS-rebinding protection) runs in web.Handler before dispatch.
  * Bodies are at most 64 KiB; every field is type- and length-checked.  Errors are
    ``{"error": <code>, "message": <text>}`` with a matching HTTP status.
  * Brute force: per-IP rate limit plus the same 5-failure lockout as the web sign-in, scoped to the device when
    it is the account's known device (accounts.MAX_FAILURES).
  * Security events go to the audit log.  Tokens, passwords, codes and keys are never logged.

Every feature is off until an administrator enables it (devices.APP_DEFAULTS).
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse

from . import accounts, auth, devices, payments, play
from .devices import DeviceError

log = logging.getLogger("pqvpn.portal")

PREFIX = "/api/v1/"
MAX_BODY = 65536
GENERIC_LOGIN = "Incorrect email/username or password, or the account is locked or disabled."


# ------------------------------------------------------------------ plumbing

def _err(h, status: int, code: str, message: str) -> None:
    h._json(status, {"error": code, "message": message})


def _text(body: dict, key: str, limit: int, required: bool = True) -> str:
    value = body.get(key, "")
    if not isinstance(value, str) or len(value) > limit or (required and not value):
        raise DeviceError(400, "bad_request", f"'{key}' is missing or invalid")
    return value


def _device(h) -> dict | None:
    header = h.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    if not 20 <= len(token) <= 100:
        return None
    return h.portal.store.vpn_device_by_token(token)


def _audit(h, action: str, detail: str, actor: str) -> None:
    h.portal.store.audit(action, actor=actor, ip=h.ip, detail=detail)


def _auditor(h):
    return lambda action, detail="", actor="": _audit(h, action, detail, actor)


def _accounts_on(h) -> dict:
    settings = h.portal.settings()
    if not devices.enabled(settings, "app_accounts"):
        raise DeviceError(404, "disabled", "accounts are not available in the app")
    return settings


def _me(h, device: dict, settings: dict | None = None) -> dict:
    settings = settings or h.portal.settings()
    selling = payments.ready(settings)
    device = h.portal.store.vpn_device(device["id"])
    play_on = h.portal.play.ready(settings)
    return devices.state(h.portal.store, device, settings, int(time.time()),
                         prices=payments.offers(settings) if selling else [], payments=selling,
                         play_product=settings["play_product_id"] if play_on else "",
                         play_account=h.portal.play.ref(device["user_id"]) if play_on and device["user_id"] else "")


def _base_url(h) -> str:
    """Absolute portal URL for links the apps open in a browser: the configured public URL, else the address the
    app reached us at (the Host header has already passed the allow-list)."""
    if h.portal.cfg.public_url:
        return h.portal.cfg.public_url.rstrip("/") + "/"
    return f"{'https' if h.portal.tls else 'http'}://{h.headers.get('Host', 'localhost')}/"


def _account_error(err: tuple[int, str]) -> DeviceError:
    status, message = err
    code = {429: "rate_limited", 503: "unavailable"}.get(status, "invalid")
    return DeviceError(status, code, message)


def dispatch(h, method: str, url: urllib.parse.SplitResult) -> None:
    body: dict = {}
    if method == "POST":
        try:
            length = int(h.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            h.close_connection = True
            return _err(h, 413 if length > 0 else 400, "bad_request", "request too large or malformed")
        raw = h.rfile.read(length)  # read before refusing, or the OS resets the connection
        h.api_raw = raw  # the exact bytes, for webhook signatures
        if not h._origin_ok():
            return _err(h, 403, "cross_site", "cross-site request blocked")
        if length:
            if not h.headers.get("Content-Type", "").startswith("application/json"):
                return _err(h, 415, "bad_request", "send application/json")
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return _err(h, 400, "bad_request", "malformed JSON")
            if not isinstance(body, dict):
                return _err(h, 400, "bad_request", "expected a JSON object")
    for m, pattern, level, fn in ROUTES:
        if m != method or not re.fullmatch(pattern, url.path):
            continue
        device = None
        if level == "device":
            device = _device(h)
            if device is None:
                return _err(h, 401, "unauthorized", "this device is not registered; reinstall or re-enroll")
            if not h.portal.allow_device(device["id"]):
                return _err(h, 429, "rate_limited", "too many requests from this device; wait a minute")
        try:
            return fn(h, body, device, url)
        except (DeviceError, payments.PaymentError, play.PlayError) as exc:
            return _err(h, exc.status, exc.code, exc.message)
        except Exception:
            log.exception("app API error on %s %s", method, url.path)
            return _err(h, 500, "internal", "internal error; the incident was logged")
    _err(h, 404, "not_found", "unknown API call")


# ------------------------------------------------------------------ enrollment

def enroll(h, body: dict, _device_row, _url) -> None:
    portal = h.portal
    settings = portal.settings()
    if not devices.enabled(settings, "app_enrollment"):
        raise DeviceError(404, "disabled", "app sign-up is not available")
    if not portal.allow_attempt(h.ip):
        raise DeviceError(429, "rate_limited", "too many requests from your network; wait a minute")
    install = devices.install_hash(portal.vault.subkey("install-id"), body.get("install_id", ""))
    device, token, cert = devices.enroll(portal.cfg, portal.store, portal.ca, settings,
                                         _text(body, "platform", 16), _text(body, "key_alg", 32),
                                         _text(body, "public_key", 8192), h.ip, install)
    restored = f"; {device['free_seconds']} s of free time kept from a reinstall" if device["free_seconds"] else ""
    _audit(h, "device_enrolled", f"{device['platform']} {device['vpn_ip']}{restored}", device["subject"])
    h._json(200, {"token": token, "profile": devices.bundle(portal.cfg, portal.ca, device, cert),
                  "me": _me(h, device, settings)})


def renew(h, body: dict, device: dict, _url) -> None:
    portal = h.portal
    cert = devices.renew(portal.cfg, portal.store, portal.ca, device, _text(body, "key_alg", 32),
                         _text(body, "public_key", 8192))
    _audit(h, "device_renewed", f"serial {cert.serial_hex[:8]}...", device["subject"])
    h._json(200, {"profile": devices.bundle(portal.cfg, portal.ca, portal.store.vpn_device(device["id"]), cert),
                  "me": _me(h, device)})


def me(h, _body, device: dict, _url) -> None:
    # Back from the checkout page: confirm a pending payment with Paddle now instead of waiting for the reconcile.
    if device["user_id"] and h.portal.store.open_pay_links(device["user_id"], time.time() - 86400):
        h.portal.payments.reconcile_user(device["user_id"])
    h._json(200, _me(h, device))


# ------------------------------------------------------------------ accounts (Pro needs sign-in)

def _login_failure(h, user: dict, device: dict, known: bool, now: int) -> None:
    """Same policy as web._register_failure: the known device has its own bucket, every other client shares the
    account's, so an attacker enrolling fresh devices cannot get more guesses."""
    store = h.portal.store
    failures = (device["failed_logins"] if known else user["failed_logins"]) + 1
    lock = now + accounts.LOCK_SECONDS if failures >= accounts.MAX_FAILURES else 0
    if known:
        store.update_vpn_device(device["id"], failed_logins=0 if lock else failures, locked_until=lock)
    else:
        store.update_user(user["id"], failed_logins=0 if lock else failures, locked_until=lock)
    _audit(h, "account_locked" if lock else "login_failed",
           f"app {'known-device ' if known else ''}failure {failures}", user["username"])


def login(h, body: dict, device: dict, _url) -> None:
    portal, store, now = h.portal, h.portal.store, int(time.time())
    settings = _accounts_on(h)
    if not portal.allow_attempt(h.ip):
        _audit(h, "login_rate_limited", "app", accounts.REDACTED_ACTOR)
        raise DeviceError(429, "rate_limited", "too many attempts from your network; wait a minute")
    login_name = _text(body, "login", 254).strip()
    password = _text(body, "password", auth.MAX_PASSWORD)
    code = _text(body, "code", 16, required=False)
    user = accounts.find_account(store, login_name)
    ok = auth.verify_password(password, user["password_hash"] if user else None)
    if user is None:
        _audit(h, "login_failed", "app: unknown user", accounts.REDACTED_ACTOR)
        raise DeviceError(401, "invalid", GENERIC_LOGIN)
    known = device["known_user_id"] == user["id"]
    if (device["locked_until"] if known else user["locked_until"]) > now:
        _audit(h, "login_locked", "app" + (" known device" if known else ""), user["username"])
        raise DeviceError(401, "invalid", GENERIC_LOGIN)
    if not ok:
        _login_failure(h, user, device, known, now)
        raise DeviceError(401, "invalid", GENERIC_LOGIN)
    if not user["enabled"]:
        _audit(h, "login_disabled", "app", user["username"])
        raise DeviceError(401, "invalid", GENERIC_LOGIN)
    if not user["email_verified"]:
        _audit(h, "login_unverified", "app", user["username"])
        raise DeviceError(403, "unverified", "verify your email first: enter the code we sent you")
    if user["totp_enabled"]:
        if not code:  # password was right: ask for the second factor without counting a failure
            raise DeviceError(401, "totp_required", "enter the 6-digit code from your authenticator app")
        step = auth.verify_totp(user["totp_secret"] or "", code, user["totp_last_step"])
        if step is None:
            _login_failure(h, user, device, known, now)
            raise DeviceError(401, "totp_invalid", "that code is not valid (or was already used)")
        store.update_user(user["id"], totp_last_step=step)
    devices.link(store, device, user, settings)
    if not known:
        store.update_user(user["id"], failed_logins=0, locked_until=0)
    store.update_user(user["id"], last_login_at=now)
    _audit(h, "login", f"app ({device['platform']}, {device['subject']})", user["username"])
    h._json(200, _me(h, device, settings))


def logout(h, _body, device: dict, _url) -> None:
    if device["user_id"]:
        user = h.portal.store.user(device["user_id"])
        devices.unlink(h.portal.store, device)
        _audit(h, "logout", f"app ({device['subject']})", user["username"] if user else "")
    h._json(200, _me(h, device))


def signup(h, body: dict, device: dict, _url) -> None:
    _accounts_on(h)
    email = _text(body, "email", 254).strip().lower()
    password = _text(body, "password", auth.MAX_PASSWORD)
    err = accounts.start_signup(h.portal, email, password, password, h.ip, _auditor(h))
    if err:
        raise _account_error(err)
    h._json(200, {"ok": True, "email": email})  # same answer whether or not the address already has an account


def signup_verify(h, body: dict, device: dict, _url) -> None:
    settings = _accounts_on(h)
    user, err = accounts.verify_signup(h.portal, _text(body, "email", 254).strip().lower(),
                                       _text(body, "code", 16), h.ip, _auditor(h))
    if err:
        raise _account_error(err)
    devices.link(h.portal.store, device, user, settings)
    _audit(h, "login", f"app sign-up ({device['platform']}, {device['subject']})", user["username"])
    h._json(200, _me(h, device, settings))


def forgot(h, body: dict, _device_row, _url) -> None:
    _accounts_on(h)
    err = accounts.request_reset(h.portal, _text(body, "login", 254).strip(), h.ip, _auditor(h), lambda _u: True)
    if err:
        raise _account_error(err)
    h._json(200, {"ok": True})


def forgot_verify(h, body: dict, _device_row, _url) -> None:
    _accounts_on(h)
    password = _text(body, "password", auth.MAX_PASSWORD)
    _user, err, _keep = accounts.complete_reset(h.portal, _text(body, "login", 254).strip(),
                                                _text(body, "code", 16), password, password, h.ip, _auditor(h))
    if err:
        raise _account_error(err)
    h._json(200, {"ok": True})


# ------------------------------------------------------------------ free time from ads

def reward_start(h, body: dict, device: dict, _url) -> None:
    settings = h.portal.settings()
    kind = _text(body, "kind", 16)
    nonce = devices.start_reward(h.portal.store, device, kind, settings, int(time.time()))
    out = {"nonce": nonce, "kind": kind, "minutes": devices.number(settings, "free_minutes")}
    if kind == "web":
        out["url"] = _base_url(h) + "reward/" + nonce
    h._json(200, out)


def reward_claim(h, body: dict, device: dict, _url) -> None:
    """Test mode only (admob_require_ssv = 0): trust the app's word that the ad was watched."""
    store, settings, now = h.portal.store, h.portal.settings(), int(time.time())
    if devices.enabled(settings, "admob_require_ssv"):
        raise DeviceError(403, "verification_required", "free time is granted when Google confirms the ad")
    reward = store.reward_by_nonce(devices.nonce_hash(_text(body, "nonce", 64)))
    if reward is None or reward["device_id"] != device["id"] or reward["kind"] != "admob":
        raise DeviceError(400, "bad_nonce", "unknown or expired ad session")
    if devices.grant(store, reward, settings, now) is None:
        raise DeviceError(409, "not_granted", "this ad was already counted, expired, or today's limit is reached")
    _audit(h, "reward_unverified", "free time granted in AdMob test mode", device["subject"])
    h._json(200, _me(h, device, settings))


def admob_ssv(h, _body, _device_row, url: urllib.parse.SplitResult) -> None:
    """Google's server-side verification callback (rewards.py).  Answers 200 once handled, so Google stops retrying."""
    store, settings, now = h.portal.store, h.portal.settings(), int(time.time())
    if not devices.enabled(settings, "admob_enabled"):
        raise DeviceError(404, "disabled", "ads are not enabled")
    try:
        params = h.portal.admob.verify(url.query, now)
    except Exception as exc:  # noqa: BLE001 -- SsvError, or OpenSSL refusing a malformed key/signature
        _audit(h, "reward_rejected", f"AdMob callback: {exc}"[:200], accounts.REDACTED_ACTOR)
        raise DeviceError(400, "bad_signature", "verification failed") from None
    reward = store.reward_by_nonce(devices.nonce_hash(params["custom_data"][:64]))
    granted = None
    if reward is not None and reward["kind"] == "admob":
        granted = devices.grant(store, reward, settings, now, "admob:" + params["transaction_id"][:100])
    h._json(200, {"ok": granted is not None})


# ------------------------------------------------------------------ Pro: payments (payments.py)

def _paying_user(h, device: dict) -> dict:
    user = h.portal.store.user(device["user_id"]) if device["user_id"] else None
    if user is None:
        raise DeviceError(401, "sign_in_required", "Pro is tied to your account: sign in or create one first")
    if not user["enabled"]:
        raise DeviceError(403, "disabled", "this account is disabled")
    return user


def checkout(h, body: dict, device: dict, _url) -> None:
    """A one-time link to Paddle's checkout for this device's account (the app opens it in the browser).

    ``period`` picks the Pro plan ("week", "month", "year"); without it (older app builds) the default plan.
    """
    user = _paying_user(h, device)
    period = _text(body, "period", 8, required=False) or payments.default_period(h.portal.settings())
    if user["paddle_subscription_id"] and devices.decide(h.portal.store, device, time.time()).plan == "premium":
        raise DeviceError(409, "already_pro", "you already have Pro; use Manage subscription to change it")
    # Each checkout creates a transaction at Paddle: cap them so an account cannot flood the Paddle account.
    if len(h.portal.store.open_pay_links(user["id"], time.time() - 3600)) >= payments.MAX_OPEN_CHECKOUTS:
        raise DeviceError(429, "rate_limited", "too many unfinished checkouts; finish one or try again later")
    code = h.portal.payments.checkout(user, period)
    _audit(h, "checkout_started", f"app ({device['subject']}), {period}", user["username"])
    h._json(200, {"url": _base_url(h) + "pay/" + code})


def manage(h, _body, device: dict, _url) -> None:
    """Paddle's customer portal (cancel, change card, receipts) for this account's subscription."""
    user = _paying_user(h, device)
    if not user["paddle_customer_id"]:
        raise DeviceError(404, "no_subscription", "this account has no subscription yet")
    url = h.portal.payments.client().portal_session(user["paddle_customer_id"], user["paddle_subscription_id"])
    if not url.startswith("https://"):
        raise DeviceError(502, "paddle", "Paddle did not return a subscription page")
    h._json(200, {"url": url})


def play_verify(h, body: dict, device: dict, _url) -> None:
    """A purchase made through Google Play Billing in the Play build: checked with Google, then applied (play.py)."""
    user = _paying_user(h, device)
    state = h.portal.play.verify(user, _text(body, "product_id", 40), _text(body, "purchase_token", 2048))
    _audit(h, "play_purchase_checked", f"app ({device['subject']}): {state.rsplit('_', 1)[-1].lower()}",
           user["username"])
    h._json(200, _me(h, device))


# ------------------------------------------------------------------ account deletion (Google Play requirement)

def delete_account(h, body: dict, device: dict, _url) -> None:
    """The signed-in account deletes itself, with its password (and authenticator code if 2FA is on).

    Its app devices become anonymous Free devices with no time (Store.delete_user).  Subscriptions are not cancelled
    here: the app tells the user to cancel them in Google Play / Paddle.  Administrators cannot delete themselves from
    an app; another administrator does it in the portal.
    """
    # Not behind the app_accounts switch: an account that is signed in here can always be deleted (user's right,
    # and Google Play's account-deletion rule), even after an administrator turned app sign-in off.
    user = _paying_user(h, device)
    store, now = h.portal.store, int(time.time())
    if not h.portal.allow_attempt(h.ip):
        raise DeviceError(429, "rate_limited", "too many attempts from your network; wait a minute")
    if user["role"] == "admin":
        raise DeviceError(403, "admin", "administrator accounts are deleted by another administrator in the portal")
    known = device["known_user_id"] == user["id"]
    if (device["locked_until"] if known else user["locked_until"]) > now:
        raise DeviceError(401, "invalid", "too many wrong passwords; try again later")
    if not auth.verify_password(_text(body, "password", auth.MAX_PASSWORD), user["password_hash"]):
        _login_failure(h, user, device, known, now)
        raise DeviceError(401, "invalid", "the password is not correct")
    if user["totp_enabled"]:
        code = _text(body, "code", 16, required=False)
        if not code:
            raise DeviceError(401, "totp_required", "enter the 6-digit code from your authenticator app")
        if auth.verify_totp(user["totp_secret"] or "", code, user["totp_last_step"]) is None:
            _login_failure(h, user, device, known, now)
            raise DeviceError(401, "totp_invalid", "that code is not valid (or was already used)")
    store.delete_user(user["id"])
    _audit(h, "account_deleted", f"by the account holder in the app ({device['subject']})", user["username"])
    h._json(200, _me(h, device))


def paddle_webhook(h, _body, _device_row, _url) -> None:
    """Paddle's notifications.  Signature-checked; the event only triggers a fresh check through Paddle's API."""
    try:
        h.portal.payments.webhook(getattr(h, "api_raw", b""), h.headers.get("Paddle-Signature", ""))
    except payments.PaymentError as exc:
        if exc.code == "bad_signature":
            _audit(h, "payment_webhook_rejected", exc.message, accounts.REDACTED_ACTOR)
        raise
    h._json(200, {"ok": True})


ROUTES = [
    ("POST", r"/api/v1/enroll", "public", enroll),
    ("POST", r"/api/v1/renew", "device", renew),
    ("GET", r"/api/v1/me", "device", me),
    ("POST", r"/api/v1/login", "device", login),
    ("POST", r"/api/v1/logout", "device", logout),
    ("POST", r"/api/v1/signup", "device", signup),
    ("POST", r"/api/v1/signup/verify", "device", signup_verify),
    ("POST", r"/api/v1/forgot", "device", forgot),
    ("POST", r"/api/v1/forgot/verify", "device", forgot_verify),
    ("POST", r"/api/v1/reward/start", "device", reward_start),
    ("POST", r"/api/v1/reward/claim", "device", reward_claim),
    ("GET", r"/api/v1/admob/ssv", "public", admob_ssv),
    ("POST", r"/api/v1/checkout", "device", checkout),
    ("POST", r"/api/v1/manage", "device", manage),
    ("POST", r"/api/v1/paddle/webhook", "public", paddle_webhook),
    ("POST", r"/api/v1/play/verify", "device", play_verify),
    ("POST", r"/api/v1/account/delete", "device", delete_account),
]
