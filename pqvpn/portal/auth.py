"""Authentication primitives, all from published standards:

  * Passwords: scrypt (RFC 7914) with OWASP's recommended cost N=2^17, r=8, p=1,
    a 16-byte random salt, constant-time comparison, and a dummy hash so that
    unknown usernames take as long as wrong passwords (no user enumeration).
  * Password policy: NIST SP 800-63B -- length (min 10, max 128), no
    composition rules, reject common/breached passwords and the username.
  * Second factor: TOTP (RFC 6238 / RFC 4226), SHA-1, 6 digits, 30 s -- the
    profile every authenticator app (Google, Microsoft, Authy, 1Password...)
    supports -- with +-1 step clock tolerance and replay protection.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import threading
import time
import urllib.parse

SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 17, 8, 1
_MAXMEM = 256 * 1024 * 1024
# Each scrypt call needs 128 MiB (128 * N * r bytes).  Bound how many run at once so a burst of sign-ins
# from many addresses queues up instead of exhausting memory.
_SCRYPT_SLOTS = threading.BoundedSemaphore(4)
DIGITS = frozenset("0123456789")


def digits_only(text: str) -> str:
    """ASCII digits of ``text`` ("123 456" -> "123456").  str.isdigit() would also keep e.g. Arabic-Indic digits."""
    return "".join(ch for ch in text if ch in DIGITS)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    with _SCRYPT_SLOTS:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=_MAXMEM, dklen=32)
MIN_PASSWORD, MAX_PASSWORD = 10, 128

# A short sample of the most common breached passwords (NIST 800-63B s5.1.1.2).
COMMON_PASSWORDS = frozenset("""
123456 123456789 12345678 password qwerty123 qwerty 1q2w3e4r 111111 123123 1234567890 000000
password1 iloveyou 1234567 abc123 password123 admin admin123 welcome welcome1 letmein
monkey dragon football baseball sunshine princess qwertyuiop asdfghjkl zxcvbnm 654321
superman trustno1 passw0rd p@ssw0rd p@ssword administrator changeme default secret
qwerty12345 1qaz2wsx 1qazxsw2 zaq12wsx pakistan pakistan123 islamabad lahore karachi
""".split())


# ------------------------------------------------------------------ passwords

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${SCRYPT_N.bit_length() - 1}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(dk)}"


_DUMMY = hash_password(secrets.token_urlsafe(16))


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check; ``stored=None`` burns the same time and fails."""
    try:
        algo, logn, r, p, salt, dk = (stored or _DUMMY).split("$")
        if algo != "scrypt":
            return False
        calc = _scrypt(password, base64.b64decode(salt), 1 << int(logn), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc, base64.b64decode(dk)) and stored is not None


def password_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD:
        problems.append(f"must be at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        problems.append(f"must be at most {MAX_PASSWORD} characters")
    low = password.lower()
    if low in COMMON_PASSWORDS or low.rstrip("0123456789!@#$") in COMMON_PASSWORDS:
        problems.append("is a commonly used password")
    if username and username.lower() in low:
        problems.append("must not contain the username")
    if len(set(password)) < 4:
        problems.append("is too repetitive")
    return problems


def generate_password() -> str:
    """Readable temporary password (~95 bits): xxxx-xxxx-xxxx-xxxx-xxxx."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(5))


# ------------------------------------------------------------------ TOTP

TOTP_STEP, TOTP_DIGITS = 30, 6


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def hotp(secret_b32: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_STEP)


def verify_totp(secret_b32: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Return the matching time step (store it!) or None.  Steps <= last_step are replays."""
    code = digits_only(code)
    if len(code) != TOTP_DIGITS:
        return None
    current = totp_step(now)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(hotp(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, account: str, issuer: str) -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    q = urllib.parse.urlencode({"secret": secret_b32, "issuer": issuer, "algorithm": "SHA1",
                                "digits": TOTP_DIGITS, "period": TOTP_STEP})
    return f"otpauth://totp/{label}?{q}"


# ------------------------------------------------------------------ tokens

def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Sessions are stored hashed: a leaked database does not leak live sessions."""
    return hashlib.sha256(token.encode()).hexdigest()
