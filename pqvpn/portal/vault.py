"""Encryption at rest for the portal secrets kept in the database.

The SMTP App Password must be readable by the portal, so it cannot be hashed.  It is sealed with
AES-256-GCM under a 256-bit key kept in a separate file (``portal-secrets.key``, mode 0600) next to
the database.  A copied or backed-up ``portal.db`` then holds only ciphertext; the key file must be
protected (and backed up) separately.

Stored form: ``enc:v1:<base64(nonce || ciphertext || tag)>``.  The setting's name is the associated
data, so a ciphertext cannot be moved to another setting.  Values without the prefix are legacy
plaintext: they still read correctly and the portal re-seals them at start-up.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from ..crypto import ossl

KEY_FILE = "portal-secrets.key"
PREFIX = "enc:v1:"
CIPHER = "AES-256-GCM"


class VaultError(Exception):
    pass


def _load_or_create(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        key = os.urandom(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # another process created it first
            return _load_or_create(path)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    if len(key) != 32:
        raise VaultError(f"{path} is not a 32-byte key")
    return key


class Vault:
    KEY_FILE = KEY_FILE

    def __init__(self, key_path: str):
        self.key_path = key_path
        self._key = _load_or_create(key_path)

    @staticmethod
    def is_sealed(value: str) -> bool:
        return value.startswith(PREFIX)

    def seal(self, name: str, plaintext: str) -> str:
        if not plaintext:
            return ""
        nonce = os.urandom(12)
        ct = ossl.AEAD(CIPHER, self._key, True).seal(nonce, name.encode(), plaintext.encode("utf-8"))
        return PREFIX + base64.b64encode(nonce + ct).decode()

    def open(self, name: str, value: str) -> str:
        if not self.is_sealed(value):
            return value  # legacy plaintext (re-sealed at start-up)
        try:
            raw = base64.b64decode(value[len(PREFIX):], validate=True)
        except ValueError:
            raise VaultError(f"setting {name} is corrupt") from None
        pt = ossl.AEAD(CIPHER, self._key, False).open(raw[:12], name.encode(), raw[12:]) if len(raw) > 12 else None
        if pt is None:
            raise VaultError(f"setting {name} cannot be decrypted with {self.key_path} (wrong or replaced key?)")
        return pt.decode("utf-8")

    def subkey(self, label: str) -> bytes:
        """An independent key for another purpose (e.g. keyed audit fingerprints)."""
        return hmac.new(self._key, b"pqvpn-portal/" + label.encode(), hashlib.sha256).digest()
