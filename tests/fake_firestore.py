"""A small stand-in for Google's OAuth token endpoint and the Firestore REST API (tests only).

It checks the RS256 service-account assertion like Google does (signature, aud, scope, iss, exp) and keeps
documents in memory, so the mirror can be tested end to end without a real Firebase project.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqvpn.crypto import ossl  # noqa: E402
from pqvpn.portal.firebase import SCOPE, TOKEN_URI  # noqa: E402

PROJECT = "pq-vpn-test"


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_key(token_uri: str = TOKEN_URI, project: str = PROJECT) -> tuple[dict, ossl.PKey]:
    """A service-account key.  ``token_uri`` is embedded in the key (must be Google's; the portal ignores it
    and uses its own fixed endpoint).  Point the *client* at a fake with Mirror(token_uri=...)."""
    pkey = ossl.generate("RSA")
    return {"type": "service_account", "project_id": project, "private_key_id": "0123abcd",
            "private_key": ossl.private_to_pem(pkey).decode(),
            "client_email": f"firebase-adminsdk-test@{project}.iam.gserviceaccount.com",
            "client_id": "1234567890", "token_uri": token_uri}, pkey


class FakeGoogle:
    def __init__(self, project: str = PROJECT):
        self.project = project
        self.docs: dict[str, dict] = {}   # "users/alice" -> REST fields
        self.commits: list[list[dict]] = []
        self.token_requests = 0
        self.firestore_error: tuple[int, dict] | None = None
        self.lock = threading.Lock()
        self.public_key: ossl.PKey | None = None
        self.client_email = ""
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, data):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.path == "/token":
                    return self._reply(*fake.token(body.decode()))
                return self._reply(*fake.firestore("POST", self.path, self.headers, body))

            def do_GET(self):
                return self._reply(*fake.firestore("GET", self.path, self.headers, b""))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.prefix = f"/v1/projects/{project}/databases/(default)/documents"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def trust(self, key: dict, pkey: ossl.PKey) -> None:
        self.public_key, self.client_email = pkey, key["client_email"]

    # -------------------------------------------------------------- OAuth 2.0 JWT bearer grant (RFC 7523)
    def token(self, form: str):
        q = dict(urllib.parse.parse_qsl(form))
        bad = (400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
        if q.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" or "assertion" not in q:
            return 400, {"error": "unsupported_grant_type"}
        try:
            h64, c64, s64 = q["assertion"].split(".")
            header, claims = json.loads(_unb64(h64)), json.loads(_unb64(c64))
        except ValueError:
            return bad
        if self.public_key is None or header.get("alg") != "RS256" or \
                not ossl.verify_hashed(self.public_key, f"{h64}.{c64}".encode(), _unb64(s64), "SHA256"):
            return bad
        now = time.time()
        if claims.get("aud") != f"{self.url}/token" or claims.get("scope") != SCOPE or \
                claims.get("iss") != self.client_email or not claims["iat"] - 60 <= now < claims["exp"]:
            return 400, {"error": "invalid_grant", "error_description": "Invalid JWT claims."}
        with self.lock:
            self.token_requests += 1
        return 200, {"access_token": "fake-access-token", "expires_in": 3599, "token_type": "Bearer"}

    # -------------------------------------------------------------- Firestore REST v1
    def firestore(self, method: str, path: str, headers, body: bytes):
        if headers.get("Authorization") != "Bearer fake-access-token":
            return 401, {"error": {"code": 401, "status": "UNAUTHENTICATED", "message": "Request had invalid "
                                                                                       "authentication credentials."}}
        if self.firestore_error:
            return self.firestore_error
        url = urllib.parse.urlsplit(path)
        p = urllib.parse.unquote(url.path)
        if not p.startswith(self.prefix):
            return 404, {"error": {"code": 404, "status": "NOT_FOUND", "message": "unknown project/database"}}
        rel = p[len(self.prefix):]
        with self.lock:
            if method == "POST" and rel == ":commit":
                writes = json.loads(body)["writes"]
                if len(writes) > 500:
                    return 400, {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                           "message": "maximum 500 writes allowed per request"}}
                full = f"projects/{self.project}/databases/(default)/documents/"
                for w in writes:
                    if "update" in w:
                        name = w["update"]["name"]
                        assert name.startswith(full), name
                        self.docs[name[len(full):]] = w["update"]["fields"]
                    else:
                        self.docs.pop(w["delete"][len(full):], None)
                self.commits.append(writes)
                return 200, {"commitTime": "2026-10-07T00:00:00Z"}
            m = re.fullmatch(r"/([^/]+)", rel)
            if method == "GET" and m:
                coll = m.group(1)
                names = sorted(k for k in self.docs if k.split("/")[0] == coll)
                return 200, {"documents": [{"name": f"projects/{self.project}/databases/(default)/documents/{n}"}
                                           for n in names]}
            m = re.fullmatch(r"/([^/]+/[^/]+)", rel)
            if method == "GET" and m:
                if m.group(1) not in self.docs:
                    return 404, {"error": {"code": 404, "status": "NOT_FOUND", "message": "Document not found"}}
                return 200, {"name": m.group(1), "fields": self.docs[m.group(1)]}
        return 400, {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": f"unsupported {method} {rel}"}}

    def value(self, path: str, field: str):
        """Decoded value of one field, for assertions."""
        v = self.docs[path][field]
        kind, raw = next(iter(v.items()))
        if kind == "integerValue":
            return int(raw)
        if kind == "arrayValue":
            return [next(iter(x.values())) for x in raw.get("values", [])]
        return raw
