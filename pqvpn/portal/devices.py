"""App-enrolled VPN devices: Free time earned by watching ads, Pro through a signed-in account.

Model (docs/SPEC.md "App devices"):

  * **Enrollment, no sign-up.**  The app generates its own ML-DSA key pair and sends only the public key; the
    portal allocates a tunnel address and issues a client certificate whose subject is a random device name
    (``d-`` + 24 base32 characters).  The private key never leaves the device (same model as ``pqvpn genkey``).
    The device authenticates to the app API with a 256-bit bearer token, stored here only as a SHA-256 hash.
  * **Plans.**  A device is *Pro* while it is linked to an enabled account whose effective plan is Premium
    (plans.effective_plan).  Otherwise it is *Free*, and may connect only while its balance ``free_seconds`` is
    above zero.  Free time is granted per watched ad -- only while the device is disconnected -- and used up only
    while it is connected: the VPN server charges connected Free devices and checks the balance on every handshake
    and every status interval (access.PortalAccess), so a modified app cannot skip the ads.
  * **Accounts.**  Signing in on a device links it to the account (at most ``pro_device_limit`` devices per
    account); signing out unlinks it.  Deleting an account turns its devices back into anonymous Free devices.

Every switch here defaults off (APP_DEFAULTS): the portal stays an admin console until an administrator turns
the app features on in Settings.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass

from .. import pki
from ..config import PortalConfig
from ..crypto.suites import sig_alg_by_name
from ..protocol import source_key
from . import auth, plans
from .store import Store

DEVICE_PREFIX = "d-"
SUBJECT_RE = re.compile(r"^d-[a-z2-7]{24}$")
INSTALL_ID_RE = re.compile(r"^[0-9a-f]{64}$")  # the app's SHA-256 of its per-app phone ID, never the raw ID
PLATFORMS = ("android", "windows")
REWARD_KINDS = ("admob", "web")
RENEW_BEFORE = 15 * 86400  # apps renew their certificate when less than this is left

APP_DEFAULTS = {
    "app_enrollment": "0",       # apps may enroll themselves (anonymous Free devices)
    "app_accounts": "0",         # apps may sign in / sign up / reset passwords (needed for Pro)
    "free_minutes": "30",        # free VPN time granted per watched ad
    "free_daily_rewards": "16",  # ads that grant time per device per 24 h
    "admob_enabled": "0",        # Android rewarded ads (Google AdMob)
    "admob_require_ssv": "1",    # grant only on Google's signed server-side callback ("0" = test mode)
    "web_ads_enabled": "0",      # Windows: ad shown on a portal web page
    "web_ads_test": "0",         # show a labelled placeholder instead of a real ad network (testing)
    "reward_min_seconds": "20",  # web ad: minimum time the page must stay open before time is granted
    "pro_device_limit": "5",     # devices one account may be signed in on at once
    "device_cleanup_days": "30",  # forget anonymous devices unseen for this long
    "enroll_per_ip_day": "20",   # enrollments per network (IPv4 address / IPv6 /64) per 24 h
    "enroll_per_hour": "300",    # enrollments per hour from all networks together (bounds CA signing work)
    "toggle_ads": "connect",     # Free devices: interstitial after "connect", after "both" connect and disconnect, "off"
    "toggle_ad_gap": "0",        # at least this many seconds between two such interstitials (0 = every time)
    "reward_gap_seconds": "10",  # wait between two ads for free time; ads may follow each other to build up time
}
TOGGLE_ADS = {"connect": "After connecting", "both": "After connecting and after disconnecting", "off": "Never"}
# A connected app sends at least a keepalive every 25 s (account_client.py); silence for longer means it is gone.
ACTIVE_SECONDS = 40
# Ads for free time are refused only while packets are still arriving, so one can follow right after Disconnect.
REWARD_IDLE_SECONDS = 12
# (min, max) for the numeric settings; the admin form and every reader clamp to these.
LIMITS = {"free_minutes": (1, 24 * 60), "free_daily_rewards": (1, 200), "reward_min_seconds": (5, 300),
          "pro_device_limit": (1, 50), "device_cleanup_days": (1, 3650), "enroll_per_ip_day": (1, 10000),
          "enroll_per_hour": (1, 100000),
          "toggle_ad_gap": (0, 3600), "reward_gap_seconds": (0, 3600)}


class DeviceError(Exception):
    """A refused app request: ``code`` is machine-readable (the apps switch on it), ``message`` is for people."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def number(settings: dict, key: str) -> int:
    lo, hi = LIMITS[key]
    try:
        value = int(settings.get(key, APP_DEFAULTS[key]))
    except ValueError:
        value = int(APP_DEFAULTS[key])
    return max(lo, min(hi, value))


def enabled(settings: dict, key: str) -> bool:
    return settings.get(key, APP_DEFAULTS.get(key, "0")) == "1"


def new_subject() -> str:
    return DEVICE_PREFIX + base64.b32encode(os.urandom(15)).decode("ascii").lower()


def is_device_subject(subject: str) -> bool:
    return bool(SUBJECT_RE.match(subject))


def nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ enrollment and certificates

def _public_key(cfg: PortalConfig, key_alg: str, public_key_b64: str) -> bytes:
    if key_alg != cfg.client_algorithm:
        raise DeviceError(400, "bad_key", f"the key must be {cfg.client_algorithm}")
    alg = sig_alg_by_name(key_alg)
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
        alg.load_public(raw)  # length and encoding checked by OpenSSL
    except Exception as exc:  # noqa: BLE001 -- any decoding failure (base64, length, OpenSSL) is the caller's fault
        raise DeviceError(400, "bad_key", "the public key is not valid") from exc
    return raw


def _issue(cfg: PortalConfig, store: Store, ca, device: dict, public_key: bytes) -> pki.Certificate:
    alg = sig_alg_by_name(cfg.client_algorithm)
    with ca.sign_slot:  # one CA signature at a time (service.CA): a burst of sign-ups cannot take every core
        cert = pki.issue(role=pki.ROLE_CLIENT, subject=device["subject"], key_alg=alg, public_key=public_key,
                         addresses=[f"{device['vpn_ip']}/32"], days=cfg.certificate_days, issuer_key=ca.key,
                         issuer_alg=ca.cert.key_alg, issuer_public=ca.cert.public_key)
    store.update_vpn_device(device["id"], active_serial=cert.serial_hex, cert_expires=cert.not_after)
    return cert


def install_hash(secret: bytes, install_id: str) -> str | None:
    """What the portal keeps of an app's install ID: a keyed hash, so the stored value is useless elsewhere."""
    if not isinstance(install_id, str) or not INSTALL_ID_RE.match(install_id):
        return None
    return hmac.new(secret, install_id.encode("ascii"), hashlib.sha256).hexdigest()


def enroll(cfg: PortalConfig, store: Store, ca, settings: dict, platform: str, key_alg: str, public_key_b64: str,
           ip: str, install: str | None = None) -> tuple[dict, str, pki.Certificate]:
    """Create an anonymous Free device; return (device row, bearer token, certificate).

    ``install`` (install_hash) identifies the phone across reinstalls: the unused Free time of its earlier
    registrations moves to this one, so time that was earned but not used is never lost by reinstalling.
    """
    if not enabled(settings, "app_enrollment"):
        raise DeviceError(404, "disabled", "app sign-up is not available")
    if platform not in PLATFORMS:
        raise DeviceError(400, "bad_platform", "unknown platform")
    raw = _public_key(cfg, key_alg, public_key_b64)
    now = int(time.time())
    network = source_key(ip)  # stored instead of the address: per-network limits, and less personal data kept
    if store.enrollments_since(network, now - 86400) >= number(settings, "enroll_per_ip_day"):
        raise DeviceError(429, "rate_limited", "too many new devices from your network today")
    if store.enrollments_since_any(now - 3600) >= number(settings, "enroll_per_hour"):
        raise DeviceError(429, "busy", "many people are signing up right now; please try again in a few minutes")
    token = auth.new_token()
    try:
        device = store.create_vpn_device(new_subject(), auth.token_hash(token), platform, cfg.subnet,
                                         set(cfg.reserved_addresses), network)
    except ValueError as exc:  # address pool exhausted
        raise DeviceError(503, "full", "the VPN server is full; please try again later") from exc
    try:
        cert = _issue(cfg, store, ca, device, raw)
    except Exception:
        store.delete_vpn_device(device["id"])
        raise
    if install:
        store.adopt_install(device["id"], install, platform)
    return store.vpn_device(device["id"]), token, cert


def renew(cfg: PortalConfig, store: Store, ca, device: dict, key_alg: str, public_key_b64: str) -> pki.Certificate:
    """A new certificate (same address) for an existing device; the old one stops working (superseded).

    Only when the current certificate is close to expiry: every issuance costs a CA signature (SLH-DSA: hundreds of
    milliseconds), so renewal on demand would let one device keep the portal busy.  A device that lost its key
    registers again instead.
    """
    if device["cert_expires"] and device["cert_expires"] - time.time() > RENEW_BEFORE:
        raise DeviceError(409, "not_due", "the certificate is not due for renewal yet")
    return _issue(cfg, store, ca, device, _public_key(cfg, key_alg, public_key_b64))


def bundle(cfg: PortalConfig, ca, device: dict, cert: pki.Certificate) -> dict:
    """Everything the app needs to build its client profile.  Contains no private key and no PSK.

    Anyone can register a device, so a PSK handed out here would no longer be secret for anybody.  App devices
    connect without one; a VPN server that has a PSK needs ``[crypto] psk_optional = true`` to accept them
    (profiles issued by an administrator keep the PSK and its extra protection).
    """
    psk = ""
    # Stealth mode: the obfuscation key is shared with every device (it is semi-public by design; see SECURITY.md),
    # so unlike the PSK it is handed out here.  Empty when the portal has no stealth key configured.
    obfs = base64.b64encode(cfg.obfuscation_key).decode() if cfg.obfuscation_key else ""
    return {
        "subject": device["subject"], "address": device["vpn_ip"], "certificate": cert.to_pem(), "ca": ca.pem,
        "server": cfg.endpoint, "server_name": cfg.server_name, "suites": list(cfg.suites),
        "ca_algorithm": ca.cert.key_alg.name, "key_algorithm": cfg.client_algorithm,
        "full_tunnel": cfg.full_tunnel, "portal_url": cfg.vpn_portal_url or cfg.public_url, "psk": psk,
        "obfuscation_key": obfs,
        "expires": cert.not_after, "renew_after": cert.not_after - RENEW_BEFORE,
    }


# ------------------------------------------------------------------ plans and VPN access

@dataclass
class Decision:
    allowed: bool
    plan: str            # "free" or "premium"
    reason: str          # why access is refused ("" when allowed)
    user: dict | None    # linked account, if any


def decide(store: Store, device: dict, now: float, cert_serial: str | None = None) -> Decision:
    """May this device use the VPN right now?  Used by the VPN server (handshakes, status sync) and the app API."""
    user = store.user(device["user_id"]) if device["user_id"] else None
    plan = plans.effective_plan(user, now) if user else "free"
    if not device["enabled"]:
        return Decision(False, plan, "device disabled by an administrator", user)
    if cert_serial is not None and (device["active_serial"] or "") != cert_serial:
        return Decision(False, plan, "certificate superseded (the device enrolled again)", user)
    if user is not None and not user["enabled"]:
        return Decision(False, plan, "account disabled", user)
    if plan == "free" and device["free_seconds"] <= 0:
        return Decision(False, plan, "free time used up: watch an ad for more", user)
    return Decision(True, plan, "", user)


def pushed_dns(user: dict | None, settings: dict, now: float) -> list[str]:
    """DNS for the device's plan: the account's own rules when signed in, else the Free plan's."""
    if user is not None:
        return plans.dns_for(user, settings, now)
    return plans.plan_dns(settings, "free")


def state(store: Store, device: dict, settings: dict, now: int, prices: list[dict] | None = None,
          payments: bool = False, play_product: str = "", play_account: str = "") -> dict:
    """What /api/v1/me reports: display data only (no tokens, keys or internal ids).

    ``prices`` are the Pro plans on sale (payments.offers); ``price_label`` repeats the monthly (else first) one for
    app builds that show a single price.  ``play_product`` / ``play_account``: Google Play billing for the Play build
    (play.py); the account reference is an HMAC, and only sent while an account is signed in.
    """
    d = decide(store, device, now)
    user = d.user
    granted = store.rewards_granted_since(device["id"], now - 86400)
    counting = d.plan == "free" and store.is_connected(device["subject"], now - 30, now - ACTIVE_SECONDS)
    prices = prices or []
    label = next((p["label"] for p in prices if p["period"] == "month"), prices[0]["label"] if prices else "")
    return {
        "now": now,
        "device": {"subject": device["subject"], "platform": device["platform"], "address": device["vpn_ip"],
                   "certificate_expires": device["cert_expires"],
                   "renew": bool(device["cert_expires"] and device["cert_expires"] - now < RENEW_BEFORE)},
        "account": ({"username": user["username"], "email": user["email"] or ""} if user else None),
        "plan": d.plan,
        "pro_until": (user["plan_expires"] if user and d.plan == "premium" else None),
        "free_seconds": device["free_seconds"],  # balance, used up only while connected
        "free_counting": counting,               # connected right now, so the balance is going down
        "free_until": now + device["free_seconds"],  # for app builds before the balance (an end time on the clock)
        "can_connect": d.allowed,
        "reason": d.reason,
        "free_minutes": number(settings, "free_minutes"),
        "rewards_left_today": max(0, number(settings, "free_daily_rewards") - granted),
        "next_reward_in": next_reward_in(store, device, settings, now),  # seconds until the next ad may start
        "features": {
            "accounts": enabled(settings, "app_accounts"),
            "admob": enabled(settings, "admob_enabled"),
            "admob_verified": enabled(settings, "admob_require_ssv"),
            "web_ads": enabled(settings, "web_ads_enabled"),
            "payments": payments,
            "play": bool(play_product),
            "toggle_ads": toggle_ads(settings),
            "toggle_ad_gap": number(settings, "toggle_ad_gap"),
        },
        "prices": prices,
        "price_label": label,
        "play": ({"product": play_product, "account": play_account} if play_product and play_account and user
                 else None),
    }


def link(store: Store, device: dict, user: dict, settings: dict) -> None:
    """Sign ``user`` in on ``device``.  Raises DeviceError when the account already uses too many devices."""
    others = [d for d in store.vpn_devices(user["id"]) if d["id"] != device["id"]]
    if len(others) >= number(settings, "pro_device_limit"):
        raise DeviceError(409, "device_limit",
                          f"this account is already signed in on {len(others)} devices; sign out on one first")
    store.update_vpn_device(device["id"], user_id=user["id"], known_user_id=user["id"], failed_logins=0,
                            locked_until=0)


def unlink(store: Store, device: dict) -> None:
    store.update_vpn_device(device["id"], user_id=None)


# ------------------------------------------------------------------ free time from ads

def start_reward(store: Store, device: dict, kind: str, settings: dict, now: int) -> str:
    """A one-time nonce for one ad view.  The ad network (or the web ad page) hands it back when it is done."""
    if kind not in REWARD_KINDS:
        raise DeviceError(400, "bad_kind", "unknown ad type")
    if not enabled(settings, "admob_enabled" if kind == "admob" else "web_ads_enabled"):
        raise DeviceError(404, "disabled", "ads are not available")
    if decide(store, device, now).plan == "premium":
        raise DeviceError(409, "pro", "Pro accounts do not need ads")
    if store.is_connected(device["subject"], now - 30, now - REWARD_IDLE_SECONDS):
        raise DeviceError(409, "connected", "disconnect first: free time is added while the VPN is off, and it is "
                          "only used while you are connected")
    if store.rewards_granted_since(device["id"], now - 86400) >= number(settings, "free_daily_rewards"):
        raise DeviceError(429, "daily_limit", "you reached today's limit of free sessions; try again tomorrow")
    if (wait := next_reward_in(store, device, settings, now)) > 0:
        raise DeviceError(429, "too_soon", f"the next ad is ready in {wait} seconds")
    nonce = secrets.token_urlsafe(24)
    store.create_reward(device["id"], kind, nonce_hash(nonce))
    return nonce


def grant(store: Store, reward: dict, settings: dict, now: int, provider_ref: str | None = None) -> int | None:
    """Credit one watched ad (single use).  Returns the device's new balance in seconds, or None if nothing was
    granted."""
    if now - reward["created_at"] > 3600:  # a nonce is good for one hour
        return None
    if store.rewards_granted_since(reward["device_id"], now - 86400) >= number(settings, "free_daily_rewards"):
        return None
    if not store.claim_reward(reward["id"], now, provider_ref):
        return None
    return store.add_free_seconds(reward["device_id"], number(settings, "free_minutes") * 60)


def next_reward_in(store: Store, device: dict, settings: dict, now: int) -> int:
    """Seconds until this device may watch the next ad for free time (0 = now).  Ads may follow each other, so
    time builds up without being used first; only a short gap (reward_gap_seconds) separates them."""
    last = store.last_reward_granted(device["id"])
    return max(0, last + number(settings, "reward_gap_seconds") - now) if last else 0


def toggle_ads(settings: dict) -> str:
    """When Free devices show an interstitial: after connecting, after connecting and disconnecting, or never."""
    value = settings.get("toggle_ads", APP_DEFAULTS["toggle_ads"])
    return value if value in TOGGLE_ADS else APP_DEFAULTS["toggle_ads"]
