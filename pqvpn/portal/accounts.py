"""Account flows shared by the web portal (web.py) and the app API (api.py).

Sign-up with email verification and password recovery follow OWASP's Forgot Password and Authentication cheat
sheets: a single-use 6-digit code stored scrypt-hashed, valid 10 minutes, 5 guesses, resend throttling, and
identical responses whether or not an account exists (no enumeration, no account takeover through sign-up).
Each function returns ``None`` on success or ``(http_status, message)``; callers render that as HTML or JSON.
``audit(action, detail, actor)`` records the event with the caller's source address.
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Callable

from . import auth, mail
from .store import Store

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$")
MAX_FAILURES, LOCK_SECONDS = 5, 15 * 60  # NIST SP 800-63B 5.2.2 throttling
RESET_TTL, RESET_MAX_ATTEMPTS, RESET_RESEND_AFTER, RESET_MAX_PER_HOUR = 10 * 60, 5, 60, 5
SIGNUP_TTL, SIGNUP_MAX_ATTEMPTS = 10 * 60, 5
REDACTED_ACTOR = "(unknown)"  # never store a typed login verbatim: it is sometimes a mistyped password
RATE_LIMITED = (429, "Too many attempts from your network. Wait a minute and try again.")
BAD_SIGNUP_CODE = "That code is not valid or has expired. Use the code from the latest email, or send a new one."
BAD_RESET_CODE = "That code is not valid or has expired. Use the code from the latest email, or send a new code."

Audit = Callable[..., None]


def mask_email(address: str) -> str:
    local, _, domain = (address or "").partition("@")
    return f"{local[:2]}***@{domain}" if domain else "-"


def find_account(store: Store, login: str) -> dict | None:
    if "@" in login:
        return store.user_by_email(login) if mail.valid_email(login) else None
    return store.user_by_name(login) if USERNAME_RE.match(login) else None


def reserved_username(name: str) -> bool:
    """``d-`` names belong to app-enrolled devices (their certificate subjects); people cannot take them."""
    return name.lower().startswith("d-")


def signup_username(store: Store, email: str) -> str:
    """A unique, valid username derived from the email's local part (it becomes the VPN certificate subject)."""
    base = re.sub(r"[^A-Za-z0-9._-]", "", email.split("@")[0]).strip("._-")[:24] or "user"
    if not base[0].isalnum():
        base = "u" + base
    base = base[:28] if len(base) >= 2 else "user"
    if reserved_username(base):
        base = "u" + base
    name = base
    while store.user_by_name(name):
        name = f"{base}-{secrets.token_hex(2)}"[:32]
    return name


def new_code() -> tuple[str, str]:
    code = f"{secrets.randbelow(10 ** 6):06d}"
    return code, auth.hash_password(code)  # the code is stored only hashed, like a password


# ------------------------------------------------------------------ sign-up

def start_signup(portal, email: str, password: str, confirm: str, ip: str, audit: Audit) -> tuple[int, str] | None:
    """Create (or refresh) an unverified Free account and email it a code.  Same answer for existing addresses."""
    store = portal.store
    if not portal.allow_attempt(ip):
        audit("signup_rate_limited", "", REDACTED_ACTOR)
        return RATE_LIMITED
    if not mail.valid_email(email):
        return 400, "Enter a valid email address."
    if password != confirm:
        return 400, "The passwords do not match."
    problems = auth.password_problems(password)
    if problems:
        return 400, "Password " + "; ".join(problems) + "."
    if not mail.is_configured(portal.settings()):
        return 503, "Sign-up by email is not available right now."
    existing = store.user_by_email(email)
    code, code_hash = new_code()
    msg = mail.verify_code_message(portal.cfg.issuer, code, SIGNUP_TTL // 60)
    if existing is None:
        username = signup_username(store, email)
        uid = store.create_user(username, "user", password, must_change=False)
        store.update_user(uid, email=email, plan="free", email_verified=0)
        store.create_reset(uid, code_hash, SIGNUP_TTL, ip)
        audit("signup_started", f"email={mask_email(email)}", username)
        portal.send_email_async(email, msg, "sign-up verification", username, ip)
    elif not existing["email_verified"]:  # re-signup of a not-yet-verified address: resend, adopt the new password
        store.update_user(existing["id"], password_hash=auth.hash_password(password))
        store.create_reset(existing["id"], code_hash, SIGNUP_TTL, ip)
        audit("signup_resend", "", existing["username"])
        portal.send_email_async(email, msg, "sign-up verification", existing["username"], ip)
    else:  # a verified account already exists: identical response, no email (no enumeration, no takeover)
        auth.hash_password(password)  # the same scrypt work as the other branches, so timing does not tell either
        audit("signup_existing", f"email={mask_email(email)}", "")
    return None


def verify_signup(portal, email: str, code: str, ip: str, audit: Audit) -> tuple[dict | None, tuple[int, str] | None]:
    """Check the emailed code; on success the account is verified and returned."""
    store = portal.store
    if not portal.allow_attempt(ip):
        return None, RATE_LIMITED
    code = auth.digits_only(code)
    user = store.user_by_email(email) if mail.valid_email(email) else None
    reset = store.active_reset(user["id"]) if user and not user["email_verified"] else None
    valid = auth.verify_password(code, reset["code_hash"] if reset else None) and len(code) == 6
    if not valid:
        if reset:
            store.reset_failed(reset["id"], SIGNUP_MAX_ATTEMPTS)
            audit("signup_code_failed", f"attempt {reset['attempts'] + 1} of {SIGNUP_MAX_ATTEMPTS}", user["username"])
        return None, (400, BAD_SIGNUP_CODE)
    if not store.consume_reset(reset["id"]):  # single use; lost a race
        return None, (400, BAD_SIGNUP_CODE)
    store.update_user(user["id"], email_verified=1)  # never re-enables an account an administrator disabled
    audit("signup_verified", f"email={mask_email(email)}", user["username"])
    return store.user(user["id"]), None


# ------------------------------------------------------------------ password recovery

def request_reset(portal, login: str, ip: str, audit: Audit, may_reset: Callable[[dict], bool]) -> tuple[int, str] | None:
    """Email a reset code if the account exists and may use it.  The caller answers identically either way."""
    store = portal.store
    if not portal.allow_attempt(ip):
        audit("password_reset_rate_limited", "", REDACTED_ACTOR)
        return RATE_LIMITED
    if not login:
        return 400, "Enter your username or email address."
    user = find_account(store, login)
    code, code_hash = new_code()  # hashed even for unknown accounts: identical timing
    now, reason = int(time.time()), ""
    if user is None:
        reason = "unknown account"
    elif not user["enabled"]:
        reason = "account disabled"
    elif not may_reset(user):
        reason = "portal is restricted to administrators"
    elif not user["email"]:
        reason = "no email address on the account"
    elif not mail.is_configured(portal.settings()):
        reason = "email is not set up"
    else:
        recent = store.resets_since(user["id"], now - 3600)
        if recent and now - recent[0]["created_at"] < RESET_RESEND_AFTER:
            reason = "throttled: previous code sent under a minute ago"
        elif len(recent) >= RESET_MAX_PER_HOUR:
            reason = f"throttled: {RESET_MAX_PER_HOUR} codes in the last hour"
    if reason:
        audit("password_reset_not_sent", reason, user["username"] if user else REDACTED_ACTOR)
        return None
    store.create_reset(user["id"], code_hash, RESET_TTL, ip)
    audit("password_reset_requested", f"code emailed to {mask_email(user['email'])}", user["username"])
    portal.send_email_async(user["email"], mail.reset_code_message(
        portal.cfg.issuer, user["username"], code, RESET_TTL // 60, ip), "password reset code", user["username"], ip)
    return None


def complete_reset(portal, login: str, code: str, new: str, confirm: str, ip: str,
                   audit: Audit) -> tuple[dict | None, tuple[int, str] | None, bool]:
    """Set a new password with an emailed code.  Returns (user, error, keep_code): keep_code means the code was
    right and only the new password was refused, so a form may show the code again."""
    store = portal.store
    if not portal.allow_attempt(ip):
        return None, RATE_LIMITED, False
    code = auth.digits_only(code)
    user = find_account(store, login)
    reset = store.active_reset(user["id"]) if user and user["enabled"] else None
    valid = auth.verify_password(code, reset["code_hash"] if reset else None) and len(code) == 6
    if not valid:
        if reset:
            store.reset_failed(reset["id"], RESET_MAX_ATTEMPTS)
            audit("password_reset_code_failed", f"attempt {reset['attempts'] + 1} of {RESET_MAX_ATTEMPTS}",
                  user["username"])
        return None, (400, BAD_RESET_CODE), False
    if new != confirm:
        return None, (400, "The new passwords do not match."), True
    problems = auth.password_problems(new, user["username"])
    if problems:
        return None, (400, "New password " + "; ".join(problems) + "."), True
    if not store.consume_reset(reset["id"]):  # lost a race with a parallel request: single use
        return None, (400, BAD_RESET_CODE), False
    store.update_user(user["id"], password_hash=auth.hash_password(new), must_change_password=0, failed_logins=0,
                      locked_until=0)
    store.delete_user_sessions(user["id"])
    store.unlink_vpn_devices(user["id"])  # an account recovery must also end sign-ins on phones and PCs
    audit("password_reset_by_email", "all sessions and app devices signed out", user["username"])
    portal.send_email_async(user["email"], mail.password_changed_message(
        portal.cfg.issuer, user["username"], ip, time.strftime("%Y-%m-%d %H:%M %Z")), "password changed notice",
        user["username"], ip)
    return user, None, False
