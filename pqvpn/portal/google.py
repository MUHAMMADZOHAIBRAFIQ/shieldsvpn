"""Google service-account sign-in, shared by the Firebase mirror (Firestore) and Google Play purchase checks.

The standard service-account flow: an RS256-signed JWT assertion exchanged for an access token (OAuth 2.0 JWT
bearer grant, RFC 7523), signed with OpenSSL (ossl.sign_hashed).  No Google client library is needed.

The token endpoint is fixed by the caller and never taken from the key file: a pasted key must not be able to make
the server send requests (and a signed assertion) anywhere else.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ..crypto import ossl

TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_TOKEN_URIS = {TOKEN_URI, "https://accounts.google.com/o/oauth2/token"}  # what Google puts in its key files


class GoogleError(Exception):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def http_error_message(exc: urllib.error.HTTPError) -> str:
    """A readable reason from one of Google's JSON error bodies (OAuth or REST)."""
    try:
        data = json.loads(exc.read() or b"{}")
    except ValueError:
        data = {}
    finally:
        exc.close()
    if not isinstance(data, dict):
        data = {}
    if "error_description" in data or isinstance(data.get("error"), str):  # OAuth token endpoint
        return f"Google rejected the key ({data.get('error_description') or data.get('error')})"
    err = data.get("error") if isinstance(data.get("error"), dict) else {}
    return f"{err.get('status') or f'HTTP {exc.code}'}: {err.get('message') or exc.reason}"


class ServiceAccount:
    """Access tokens for one service-account key and one OAuth scope, and authenticated JSON requests."""

    error: type[GoogleError] = GoogleError

    def __init__(self, key: dict, scope: str, timeout: float = 20, token_uri: str = TOKEN_URI):
        self.key, self.scope, self.email = key, scope, key["client_email"]
        self._pkey = ossl.private_from_pem(key["private_key"].encode())
        self.timeout = timeout
        self.token_uri = token_uri  # fixed by the caller (tests point it at a fake), never taken from the key
        self._token, self._token_expiry = "", 0.0

    def _assertion(self) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        if self.key.get("private_key_id"):
            header["kid"] = self.key["private_key_id"]
        claims = {"iss": self.email, "scope": self.scope, "aud": self.token_uri, "iat": now, "exp": now + 3600}
        signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
        return f"{signing_input}.{b64url(ossl.sign_hashed(self._pkey, signing_input.encode(), 'SHA256'))}"

    def token(self) -> str:
        if self._token and time.time() < self._token_expiry - 120:
            return self._token
        body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": self._assertion()}).encode()
        data = self._http("POST", self.token_uri, body, {"Content-Type": "application/x-www-form-urlencoded"})
        try:
            self._token = str(data["access_token"])
            self._token_expiry = time.time() + int(data.get("expires_in", 3600))
        except (KeyError, TypeError, ValueError):
            raise self.error("Google's token endpoint sent an unexpected answer") from None
        return self._token

    def _describe(self, exc: urllib.error.HTTPError) -> str:
        return http_error_message(exc)

    def _http(self, method: str, url: str, body: bytes | None, headers: dict) -> dict:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 -- fixed Google hosts
                data = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise self.error(self._describe(exc)) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise self.error(f"cannot reach Google ({getattr(exc, 'reason', exc)})") from None
        except ValueError:
            raise self.error("Google sent an answer that is not JSON") from None
        if not isinstance(data, dict):
            raise self.error("Google sent an unexpected answer")
        return data

    def _api(self, method: str, url: str, payload: dict | None = None) -> dict:
        body = json.dumps(payload).encode() if payload is not None else None
        return self._http(method, url, body, {"Authorization": f"Bearer {self.token()}",
                                              "Content-Type": "application/json"})
