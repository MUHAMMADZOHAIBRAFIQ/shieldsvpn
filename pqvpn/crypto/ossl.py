"""Thin ctypes binding to OpenSSL libcrypto (>= 3.5).

Every cryptographic primitive used by pqvpn is executed inside OpenSSL; this
module only marshals buffers.  OpenSSL 3.5 is the first release with native,
FIPS 203/204/205 implementations of ML-KEM, ML-DSA and SLH-DSA.

The library is located in this order:
  1. $PQVPN_LIBCRYPTO (absolute path to libcrypto)
  2. the libcrypto already loaded by Python's own ``ssl`` module
  3. platform default names / ctypes.util.find_library
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char_p,
    c_int,
    c_long,
    c_size_t,
    c_uint,
    c_ulong,
    c_void_p,
)

MIN_OPENSSL_VERSION = 0x30500000  # 3.5.0


class OpenSSLError(Exception):
    """Raised when an OpenSSL call fails; carries the drained error queue."""


class OSSL_PARAM(Structure):
    _fields_ = [
        ("key", c_char_p),
        ("data_type", c_uint),
        ("data", c_void_p),
        ("data_size", c_size_t),
        ("return_size", c_size_t),
    ]


OSSL_PARAM_UTF8_STRING = 4
OSSL_PARAM_OCTET_STRING = 5
OSSL_PARAM_UNMODIFIED = ctypes.c_size_t(-1).value

EVP_PKEY_PUBLIC_KEY = 0x86  # OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | PUBLIC_KEY
EVP_CTRL_AEAD_GET_TAG = 0x10
EVP_CTRL_AEAD_SET_TAG = 0x11
BIO_CTRL_INFO = 3


def _candidate_paths() -> list[str]:
    paths: list[str] = []
    env = os.environ.get("PQVPN_LIBCRYPTO")
    if env:
        paths.append(env)
    if sys.platform == "win32":
        import ssl  # noqa: F401  -- forces Python's libcrypto into the process

        paths += ["libcrypto-3-x64.dll", "libcrypto-3.dll"]
        exe_dir = os.path.dirname(sys.executable)
        for name in ("libcrypto-3-x64.dll", "libcrypto-3.dll"):
            paths.append(os.path.join(exe_dir, name))
            paths.append(os.path.join(exe_dir, "DLLs", name))
    elif sys.platform == "darwin":
        paths += [
            "libcrypto.3.dylib",
            "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
            "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
        ]
    else:
        paths += ["libcrypto.so.3"]
    found = ctypes.util.find_library("crypto")
    if found:
        paths.append(found)
    return paths


def _load() -> ctypes.CDLL:
    errors = []
    for path in _candidate_paths():
        try:
            lib = ctypes.CDLL(path)
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            continue
        lib.OpenSSL_version_num.restype = c_ulong
        version = lib.OpenSSL_version_num()
        if version >= MIN_OPENSSL_VERSION:
            return lib
        errors.append(f"{path}: version 0x{version:08x} is older than 3.5.0")
    raise OpenSSLError(
        "OpenSSL >= 3.5 libcrypto not found (needed for ML-KEM/ML-DSA/SLH-DSA). "
        "Set PQVPN_LIBCRYPTO to its path. Tried:\n  " + "\n  ".join(errors)
    )


lib = _load()

_SIGNATURES = {
    "OpenSSL_version": (c_char_p, [c_int]),
    "ERR_get_error": (c_ulong, []),
    "ERR_error_string_n": (None, [c_ulong, c_char_p, c_size_t]),
    "ERR_clear_error": (None, []),
    "CRYPTO_free": (None, [c_void_p, c_char_p, c_int]),
    # EVP_PKEY
    "EVP_PKEY_CTX_new_from_name": (c_void_p, [c_void_p, c_char_p, c_char_p]),
    "EVP_PKEY_CTX_new_from_pkey": (c_void_p, [c_void_p, c_void_p, c_char_p]),
    "EVP_PKEY_CTX_free": (None, [c_void_p]),
    "EVP_PKEY_CTX_set_group_name": (c_int, [c_void_p, c_char_p]),
    "EVP_PKEY_keygen_init": (c_int, [c_void_p]),
    "EVP_PKEY_generate": (c_int, [c_void_p, POINTER(c_void_p)]),
    "EVP_PKEY_fromdata_init": (c_int, [c_void_p]),
    "EVP_PKEY_fromdata": (c_int, [c_void_p, POINTER(c_void_p), c_int, POINTER(OSSL_PARAM)]),
    "EVP_PKEY_free": (None, [c_void_p]),
    "EVP_PKEY_is_a": (c_int, [c_void_p, c_char_p]),
    "EVP_PKEY_get_raw_public_key": (c_int, [c_void_p, c_char_p, POINTER(c_size_t)]),
    "EVP_PKEY_get1_encoded_public_key": (c_size_t, [c_void_p, POINTER(c_void_p)]),
    "EVP_PKEY_new_raw_public_key_ex": (c_void_p, [c_void_p, c_char_p, c_char_p, c_char_p, c_size_t]),
    "EVP_PKEY_encapsulate_init": (c_int, [c_void_p, c_void_p]),
    "EVP_PKEY_encapsulate": (c_int, [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, POINTER(c_size_t)]),
    "EVP_PKEY_decapsulate_init": (c_int, [c_void_p, c_void_p]),
    "EVP_PKEY_decapsulate": (c_int, [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t]),
    "EVP_PKEY_derive_init": (c_int, [c_void_p]),
    "EVP_PKEY_derive_set_peer_ex": (c_int, [c_void_p, c_void_p, c_int]),
    "EVP_PKEY_derive": (c_int, [c_void_p, c_char_p, POINTER(c_size_t)]),
    # signatures
    "EVP_MD_CTX_new": (c_void_p, []),
    "EVP_MD_CTX_free": (None, [c_void_p]),
    "EVP_DigestSignInit_ex": (c_int, [c_void_p, c_void_p, c_char_p, c_void_p, c_char_p, c_void_p, POINTER(OSSL_PARAM)]),
    "EVP_DigestSign": (c_int, [c_void_p, c_char_p, POINTER(c_size_t), c_char_p, c_size_t]),
    "EVP_DigestVerifyInit_ex": (c_int, [c_void_p, c_void_p, c_char_p, c_void_p, c_char_p, c_void_p, POINTER(OSSL_PARAM)]),
    "EVP_DigestVerify": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t]),
    # PEM / BIO
    "BIO_s_mem": (c_void_p, []),
    "BIO_new": (c_void_p, [c_void_p]),
    "BIO_new_mem_buf": (c_void_p, [c_char_p, c_int]),
    "BIO_free": (c_int, [c_void_p]),
    "BIO_ctrl": (c_long, [c_void_p, c_int, c_long, c_void_p]),
    "PEM_write_bio_PrivateKey": (c_int, [c_void_p, c_void_p, c_void_p, c_char_p, c_int, c_void_p, c_void_p]),
    "PEM_write_bio_PKCS8PrivateKey": (c_int, [c_void_p, c_void_p, c_void_p, c_char_p, c_int, c_void_p, c_char_p]),
    "PEM_read_bio_PrivateKey": (c_void_p, [c_void_p, c_void_p, c_void_p, c_char_p]),
    "PEM_write_bio_PUBKEY": (c_int, [c_void_p, c_void_p]),
    "PEM_read_bio_PUBKEY": (c_void_p, [c_void_p, c_void_p, c_void_p, c_void_p]),
    "EVP_aes_256_cbc": (c_void_p, []),
    # symmetric AEAD
    "EVP_CIPHER_fetch": (c_void_p, [c_void_p, c_char_p, c_char_p]),
    "EVP_CIPHER_free": (None, [c_void_p]),
    "EVP_CIPHER_CTX_new": (c_void_p, []),
    "EVP_CIPHER_CTX_free": (None, [c_void_p]),
    "EVP_CIPHER_CTX_ctrl": (c_int, [c_void_p, c_int, c_int, c_void_p]),
    "EVP_EncryptInit_ex2": (c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_void_p]),
    "EVP_EncryptUpdate": (c_int, [c_void_p, c_void_p, POINTER(c_int), c_char_p, c_int]),
    "EVP_EncryptFinal_ex": (c_int, [c_void_p, c_void_p, POINTER(c_int)]),
    "EVP_DecryptInit_ex2": (c_int, [c_void_p, c_void_p, c_char_p, c_char_p, c_void_p]),
    "EVP_DecryptUpdate": (c_int, [c_void_p, c_void_p, POINTER(c_int), c_char_p, c_int]),
    "EVP_DecryptFinal_ex": (c_int, [c_void_p, c_void_p, POINTER(c_int)]),
}

for _name, (_res, _args) in _SIGNATURES.items():
    _fn = getattr(lib, _name)
    _fn.restype = _res
    _fn.argtypes = _args


def version_string() -> str:
    return lib.OpenSSL_version(0).decode()


def error_queue() -> str:
    msgs = []
    while True:
        code = lib.ERR_get_error()
        if not code:
            break
        buf = ctypes.create_string_buffer(256)
        lib.ERR_error_string_n(code, buf, len(buf))
        msgs.append(buf.value.decode(errors="replace"))
    return "; ".join(msgs) or "unknown OpenSSL error"


def check(ok, what: str):
    """Raise OpenSSLError unless ``ok`` is a positive int / non-NULL pointer."""
    if not ok or (isinstance(ok, int) and ok <= 0):
        raise OpenSSLError(f"{what} failed: {error_queue()}")
    return ok


def octet_params(**items: bytes) -> ctypes.Array:
    """Build a NULL-terminated OSSL_PARAM array of octet strings.

    Keyword names use ``_`` for ``-`` (``context_string`` -> ``context-string``).
    The returned array keeps references to its buffers alive.
    """
    arr = (OSSL_PARAM * (len(items) + 1))()
    keep = []
    for i, (key, value) in enumerate(items.items()):
        buf = ctypes.create_string_buffer(value, len(value))
        keep.append(buf)
        arr[i] = OSSL_PARAM(key.replace("_", "-").encode(), OSSL_PARAM_OCTET_STRING,
                            ctypes.cast(buf, c_void_p), len(value), OSSL_PARAM_UNMODIFIED)
    arr._keep = keep  # type: ignore[attr-defined]
    return arr


class PKey:
    """Owning handle for an EVP_PKEY*."""

    __slots__ = ("ptr",)

    def __init__(self, ptr: int):
        self.ptr = check(ptr, "EVP_PKEY allocation")

    def __del__(self):
        ptr, self.ptr = getattr(self, "ptr", None), None
        if ptr:
            lib.EVP_PKEY_free(ptr)

    def is_a(self, name: str) -> bool:
        return lib.EVP_PKEY_is_a(self.ptr, name.encode()) == 1


class _PKeyCtx:
    def __init__(self, ptr: int, what: str):
        self.ptr = check(ptr, what)

    def __enter__(self):
        return self.ptr

    def __exit__(self, *exc):
        lib.EVP_PKEY_CTX_free(self.ptr)


def ctx_from_name(name: str) -> _PKeyCtx:
    return _PKeyCtx(lib.EVP_PKEY_CTX_new_from_name(None, name.encode(), None), f"EVP_PKEY_CTX({name})")


def ctx_from_pkey(key: PKey) -> _PKeyCtx:
    return _PKeyCtx(lib.EVP_PKEY_CTX_new_from_pkey(None, key.ptr, None), "EVP_PKEY_CTX_new_from_pkey")


def generate(name: str, group: str | None = None) -> PKey:
    with ctx_from_name(name) as ctx:
        check(lib.EVP_PKEY_keygen_init(ctx), f"keygen_init({name})")
        if group:
            check(lib.EVP_PKEY_CTX_set_group_name(ctx, group.encode()), f"set_group({group})")
        out = c_void_p()
        check(lib.EVP_PKEY_generate(ctx, byref(out)), f"generate({name})")
        return PKey(out.value)


def raw_public(key: PKey) -> bytes:
    n = c_size_t(0)
    check(lib.EVP_PKEY_get_raw_public_key(key.ptr, None, byref(n)), "get_raw_public_key(len)")
    buf = ctypes.create_string_buffer(n.value)
    check(lib.EVP_PKEY_get_raw_public_key(key.ptr, buf, byref(n)), "get_raw_public_key")
    return buf.raw[: n.value]


def load_raw_public(name: str, data: bytes) -> PKey:
    # For ML-KEM this performs the FIPS 203 encapsulation-key input check.
    return PKey(lib.EVP_PKEY_new_raw_public_key_ex(None, name.encode(), None, data, len(data)))


def encoded_public(key: PKey) -> bytes:
    """Encoded (uncompressed SEC1) public key, used for NIST curves."""
    ptr = c_void_p()
    n = lib.EVP_PKEY_get1_encoded_public_key(key.ptr, byref(ptr))
    check(n, "get1_encoded_public_key")
    try:
        return ctypes.string_at(ptr, n)
    finally:
        lib.CRYPTO_free(ptr, None, 0)


def load_ec_public(group: str, data: bytes) -> PKey:
    group_b = ctypes.create_string_buffer(group.encode())
    pub_b = ctypes.create_string_buffer(data, len(data))
    params = (OSSL_PARAM * 3)()
    params[0] = OSSL_PARAM(b"group", OSSL_PARAM_UTF8_STRING, ctypes.cast(group_b, c_void_p),
                           len(group), OSSL_PARAM_UNMODIFIED)
    params[1] = OSSL_PARAM(b"pub", OSSL_PARAM_OCTET_STRING, ctypes.cast(pub_b, c_void_p),
                           len(data), OSSL_PARAM_UNMODIFIED)
    with ctx_from_name("EC") as ctx:
        check(lib.EVP_PKEY_fromdata_init(ctx), "fromdata_init(EC)")
        out = c_void_p()
        check(lib.EVP_PKEY_fromdata(ctx, byref(out), EVP_PKEY_PUBLIC_KEY, params), "fromdata(EC)")
        return PKey(out.value)


def derive(own: PKey, peer: PKey) -> bytes:
    with ctx_from_pkey(own) as ctx:
        check(lib.EVP_PKEY_derive_init(ctx), "derive_init")
        # validate=1 runs EVP_PKEY_public_check on the peer key
        check(lib.EVP_PKEY_derive_set_peer_ex(ctx, peer.ptr, 1), "derive_set_peer")
        n = c_size_t(0)
        check(lib.EVP_PKEY_derive(ctx, None, byref(n)), "derive(len)")
        buf = ctypes.create_string_buffer(n.value)
        check(lib.EVP_PKEY_derive(ctx, buf, byref(n)), "derive")
        return buf.raw[: n.value]


def encapsulate(pub: PKey) -> tuple[bytes, bytes]:
    with ctx_from_pkey(pub) as ctx:
        check(lib.EVP_PKEY_encapsulate_init(ctx, None), "encapsulate_init")
        ct_len, ss_len = c_size_t(0), c_size_t(0)
        check(lib.EVP_PKEY_encapsulate(ctx, None, byref(ct_len), None, byref(ss_len)), "encapsulate(len)")
        ct = ctypes.create_string_buffer(ct_len.value)
        ss = ctypes.create_string_buffer(ss_len.value)
        check(lib.EVP_PKEY_encapsulate(ctx, ct, byref(ct_len), ss, byref(ss_len)), "encapsulate")
        return ct.raw[: ct_len.value], ss.raw[: ss_len.value]


def decapsulate(priv: PKey, ct: bytes) -> bytes:
    with ctx_from_pkey(priv) as ctx:
        check(lib.EVP_PKEY_decapsulate_init(ctx, None), "decapsulate_init")
        n = c_size_t(0)
        check(lib.EVP_PKEY_decapsulate(ctx, None, byref(n), ct, len(ct)), "decapsulate(len)")
        ss = ctypes.create_string_buffer(n.value)
        check(lib.EVP_PKEY_decapsulate(ctx, ss, byref(n), ct, len(ct)), "decapsulate")
        return ss.raw[: n.value]


class _MDCtx:
    def __enter__(self):
        self.ptr = check(lib.EVP_MD_CTX_new(), "EVP_MD_CTX_new")
        return self.ptr

    def __exit__(self, *exc):
        lib.EVP_MD_CTX_free(self.ptr)


def sign(priv: PKey, msg: bytes, context: bytes) -> bytes:
    """Pure (one-shot) ML-DSA / SLH-DSA signature with a FIPS 204/205 context string."""
    params = octet_params(context_string=context)
    with _MDCtx() as mctx:
        check(lib.EVP_DigestSignInit_ex(mctx, None, None, None, None, priv.ptr, params), "DigestSignInit")
        n = c_size_t(0)
        check(lib.EVP_DigestSign(mctx, None, byref(n), msg, len(msg)), "DigestSign(len)")
        sig = ctypes.create_string_buffer(n.value)
        check(lib.EVP_DigestSign(mctx, sig, byref(n), msg, len(msg)), "DigestSign")
        return sig.raw[: n.value]


def verify(pub: PKey, msg: bytes, sig: bytes, context: bytes) -> bool:
    params = octet_params(context_string=context)
    with _MDCtx() as mctx:
        check(lib.EVP_DigestVerifyInit_ex(mctx, None, None, None, None, pub.ptr, params), "DigestVerifyInit")
        ok = lib.EVP_DigestVerify(mctx, sig, len(sig), msg, len(msg))
        lib.ERR_clear_error()
        return ok == 1


def sign_hashed(priv: PKey, msg: bytes, digest: str = "SHA256") -> bytes:
    """Classical hash-then-sign; for an RSA key this is RSASSA-PKCS1-v1_5 (JWT "RS256" with SHA256).

    Not used by the VPN protocol: it signs the OAuth assertion for the optional Firebase mirror.
    """
    with _MDCtx() as mctx:
        check(lib.EVP_DigestSignInit_ex(mctx, None, digest.encode(), None, None, priv.ptr, None),
              f"DigestSignInit({digest})")
        n = c_size_t(0)
        check(lib.EVP_DigestSign(mctx, None, byref(n), msg, len(msg)), "DigestSign(len)")
        sig = ctypes.create_string_buffer(n.value)
        check(lib.EVP_DigestSign(mctx, sig, byref(n), msg, len(msg)), "DigestSign")
        return sig.raw[: n.value]


def verify_hashed(pub: PKey, msg: bytes, sig: bytes, digest: str = "SHA256") -> bool:
    with _MDCtx() as mctx:
        check(lib.EVP_DigestVerifyInit_ex(mctx, None, digest.encode(), None, None, pub.ptr, None),
              f"DigestVerifyInit({digest})")
        ok = lib.EVP_DigestVerify(mctx, sig, len(sig), msg, len(msg))
        lib.ERR_clear_error()
        return ok == 1


# ----------------------------------------------------------------- PEM I/O

class _Bio:
    def __init__(self, data: bytes | None = None):
        if data is None:
            self.ptr = check(lib.BIO_new(lib.BIO_s_mem()), "BIO_new")
        else:
            self._data = data
            self.ptr = check(lib.BIO_new_mem_buf(data, len(data)), "BIO_new_mem_buf")

    def contents(self) -> bytes:
        p = c_void_p()
        n = lib.BIO_ctrl(self.ptr, BIO_CTRL_INFO, 0, byref(p))
        return ctypes.string_at(p, n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        lib.BIO_free(self.ptr)


def private_to_pem(key: PKey, passphrase: bytes | None = None) -> bytes:
    with _Bio() as bio:
        if passphrase:
            # PKCS#8 PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC)
            check(lib.PEM_write_bio_PKCS8PrivateKey(bio.ptr, key.ptr, lib.EVP_aes_256_cbc(),
                                                    None, 0, None, passphrase), "PEM_write(PKCS8)")
        else:
            check(lib.PEM_write_bio_PrivateKey(bio.ptr, key.ptr, None, None, 0, None, None), "PEM_write")
        return bio.contents()


def private_from_pem(pem: bytes, passphrase: bytes | None = None) -> PKey:
    with _Bio(pem) as bio:
        # With a NULL callback OpenSSL treats the last argument as the passphrase.
        ptr = lib.PEM_read_bio_PrivateKey(bio.ptr, None, None, passphrase or b"")
        if not ptr:
            raise OpenSSLError(f"cannot read private key (wrong passphrase?): {error_queue()}")
        return PKey(ptr)


def public_to_pem(key: PKey) -> bytes:
    with _Bio() as bio:
        check(lib.PEM_write_bio_PUBKEY(bio.ptr, key.ptr), "PEM_write_PUBKEY")
        return bio.contents()


def public_from_pem(pem: bytes) -> PKey:
    with _Bio(pem) as bio:
        return PKey(lib.PEM_read_bio_PUBKEY(bio.ptr, None, None, None))


# ----------------------------------------------------------------- AEAD

class AEAD:
    """One direction of an AEAD key with a pre-keyed, reusable cipher context.

    Only the 12-byte nonce changes per packet, so each call is a handful of
    cheap OpenSSL calls with no key schedule recomputation.
    """

    TAG = 16
    _ciphers: dict[str, int] = {}

    def __init__(self, cipher_name: str, key: bytes, encrypt: bool):
        cipher = self._ciphers.get(cipher_name)
        if cipher is None:
            cipher = check(lib.EVP_CIPHER_fetch(None, cipher_name.encode(), None), f"fetch({cipher_name})")
            self._ciphers[cipher_name] = cipher
        self.encrypt = encrypt
        self.ctx = check(lib.EVP_CIPHER_CTX_new(), "EVP_CIPHER_CTX_new")
        init = lib.EVP_EncryptInit_ex2 if encrypt else lib.EVP_DecryptInit_ex2
        check(init(self.ctx, cipher, key, None, None), "CipherInit(key)")
        self._outl = c_int(0)

    def __del__(self):
        ctx, self.ctx = getattr(self, "ctx", None), None
        if ctx:
            lib.EVP_CIPHER_CTX_free(ctx)

    def seal(self, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        assert self.encrypt and len(nonce) == 12
        ctx, outl = self.ctx, self._outl
        check(lib.EVP_EncryptInit_ex2(ctx, None, None, nonce, None), "EncryptInit(iv)")
        if aad:
            check(lib.EVP_EncryptUpdate(ctx, None, byref(outl), aad, len(aad)), "EncryptUpdate(aad)")
        n = len(plaintext)
        out = ctypes.create_string_buffer(n + self.TAG)
        if n:
            check(lib.EVP_EncryptUpdate(ctx, out, byref(outl), plaintext, n), "EncryptUpdate")
        check(lib.EVP_EncryptFinal_ex(ctx, None, byref(outl)), "EncryptFinal")
        check(lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, self.TAG,
                                      ctypes.byref(out, n)), "GET_TAG")
        return out.raw

    def open(self, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes | None:
        """Return the plaintext, or None if authentication fails."""
        assert not self.encrypt and len(nonce) == 12
        n = len(ciphertext) - self.TAG
        if n < 0:
            return None
        ctx, outl = self.ctx, self._outl
        check(lib.EVP_DecryptInit_ex2(ctx, None, None, nonce, None), "DecryptInit(iv)")
        if aad:
            check(lib.EVP_DecryptUpdate(ctx, None, byref(outl), aad, len(aad)), "DecryptUpdate(aad)")
        out = ctypes.create_string_buffer(max(n, 1))
        if n:
            check(lib.EVP_DecryptUpdate(ctx, out, byref(outl), ciphertext, n), "DecryptUpdate")
        tag = ctypes.create_string_buffer(ciphertext[n:], self.TAG)
        check(lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, self.TAG, tag), "SET_TAG")
        if lib.EVP_DecryptFinal_ex(ctx, None, byref(outl)) != 1:
            lib.ERR_clear_error()
            return None
        return out.raw[:n]
