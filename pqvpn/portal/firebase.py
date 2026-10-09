"""One-way mirror of the portal database into Firebase (Cloud Firestore).

SQLite stays the source of truth: the VPN server checks it at every
handshake, so the VPN keeps working when the internet or Firebase is down.
The portal copies a read-only view into Firestore so it can be browsed in
the Firebase console or used by other apps:

    users/{username}        account, role, plan, DNS, status (no secrets)
    connections/{username}  live VPN sessions (removed on disconnect)
    status/server           online/offline and counts
    settings/portal         plans, DNS and access settings (no email password)
    audit/{id}              the audit log, append-only

Only allow-listed fields are uploaded: password hashes, TOTP secrets,
sessions, reset codes and the SMTP password never leave the server.

Writes are minimised for Firebase's free tier (20k writes/day): a document is
written only when it changes, and live traffic counters / the server
heartbeat are refreshed at most every TRAFFIC_INTERVAL seconds.

Authentication is the standard service-account flow (RFC 7523 JWT bearer
grant, RS256 signed with OpenSSL), then Firestore's REST API -- no extra
Python packages.  The key file lives next to the database with mode 0600.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .. import __version__
from ..crypto import ossl
from ..crypto.suites import describe_suite
from . import mail, plans

log = logging.getLogger("pqvpn.firebase")

FIRESTORE = "https://firestore.googleapis.com/v1"
SCOPE = "https://www.googleapis.com/auth/datastore"
# The key file's own token_uri is never used as a URL: a pasted key must not be able to make the server
# send requests (and a signed assertion) anywhere else.  These are the values Google puts in its keys.
TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_TOKEN_URIS = {TOKEN_URI, "https://accounts.google.com/o/oauth2/token"}
PROJECT_ID_RE = re.compile(r"^(?:[a-z0-9.-]{1,63}:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$")  # optional legacy domain prefix
KEY_FILE = "firebase-key.json"
SYNC_INTERVAL, TRAFFIC_INTERVAL, MAX_BACKOFF = 10, 300, 300
BATCH, AUDIT_PER_SYNC = 500, 2000
MIRRORED_COLLECTIONS = ("users", "connections")  # reconciled (stale documents are deleted)


class FirebaseError(Exception):
    pass


# ------------------------------------------------------------------ service-account key

def parse_key(text: str) -> dict:
    """Validate a Firebase / Google Cloud service-account key (the downloaded .json)."""
    try:
        key = json.loads(text)
    except ValueError:
        raise FirebaseError("that is not valid JSON; paste the whole downloaded key file") from None
    if not isinstance(key, dict) or key.get("type") != "service_account":
        raise FirebaseError('not a service-account key (expected "type": "service_account")')
    for field in ("project_id", "client_email", "private_key"):
        if not isinstance(key.get(field), str) or not key[field]:
            raise FirebaseError(f"the key file has no {field}")
    if not PROJECT_ID_RE.match(key["project_id"]):
        raise FirebaseError("the key's project_id is not a valid Google Cloud project ID")
    if key.get("token_uri", TOKEN_URI) not in GOOGLE_TOKEN_URIS:
        raise FirebaseError("the key's token_uri is not Google's token endpoint; paste the unmodified key file")
    try:
        if not ossl.private_from_pem(key["private_key"].encode()).is_a("RSA"):
            raise FirebaseError("the key's private_key is not an RSA key")
    except ossl.OpenSSLError:
        raise FirebaseError("the key's private_key cannot be read") from None
    return key


def load_key(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return parse_key(f.read())
    except FileNotFoundError:
        return None


def save_key(path: str, key: dict) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(key, f, indent=2)
    os.replace(tmp, path)


# ------------------------------------------------------------------ Firestore REST client

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def encode_value(v) -> dict:
    """Python value -> Firestore REST Value."""
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, Timestamp):
        return {"timestampValue": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(v.seconds))}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [encode_value(x) for x in v]}}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {k: encode_value(x) for k, x in v.items()}}}
    return {"stringValue": str(v)}


class Timestamp:
    __slots__ = ("seconds",)

    def __init__(self, seconds: int):
        self.seconds = int(seconds)

    def __eq__(self, other):
        return isinstance(other, Timestamp) and other.seconds == self.seconds

    def __repr__(self):
        return f"Timestamp({self.seconds})"


def ts(value) -> Timestamp | None:
    return Timestamp(value) if value else None


class Client:
    def __init__(self, key: dict, endpoint: str = FIRESTORE, database: str = "(default)", timeout: float = 20,
                 token_uri: str = TOKEN_URI):
        self.key, self.project, self.email = key, key["project_id"], key["client_email"]
        self._pkey = ossl.private_from_pem(key["private_key"].encode())
        self.prefix = f"projects/{urllib.parse.quote(self.project, safe=':')}/databases/{database}/documents"
        self.base = f"{endpoint.rstrip('/')}/{self.prefix}"
        self.timeout = timeout
        self.token_uri = token_uri  # fixed by the portal (tests point it at a fake), never taken from the key
        self._token, self._token_expiry = "", 0.0

    def _assertion(self) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        if self.key.get("private_key_id"):
            header["kid"] = self.key["private_key_id"]
        claims = {"iss": self.email, "scope": SCOPE, "aud": self.token_uri, "iat": now, "exp": now + 3600}
        signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
        return f"{signing_input}.{_b64url(ossl.sign_hashed(self._pkey, signing_input.encode(), 'SHA256'))}"

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
            raise FirebaseError("Google's token endpoint sent an unexpected answer") from None
        return self._token

    def _http(self, method: str, url: str, body: bytes | None, headers: dict) -> dict:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise FirebaseError(_google_error(exc)) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise FirebaseError(f"cannot reach Google ({getattr(exc, 'reason', exc)})") from None
        except ValueError:
            raise FirebaseError("Google sent an answer that is not JSON") from None
        if not isinstance(data, dict):
            raise FirebaseError("Google sent an unexpected answer")
        return data

    def _api(self, method: str, url: str, payload: dict | None = None) -> dict:
        body = json.dumps(payload).encode() if payload is not None else None
        return self._http(method, url, body, {"Authorization": f"Bearer {self.token()}",
                                              "Content-Type": "application/json"})

    def commit(self, writes: list[dict]) -> None:
        for i in range(0, len(writes), BATCH):
            self._api("POST", f"{self.base}:commit", {"writes": writes[i:i + BATCH]})

    def update(self, path: str, fields: dict) -> dict:
        return {"update": {"name": f"{self.prefix}/{path}", "fields": {k: encode_value(v) for k, v in fields.items()}}}

    def delete(self, path: str) -> dict:
        return {"delete": f"{self.prefix}/{path}"}

    def list_ids(self, collection: str) -> list[str]:
        ids, page = [], ""
        while True:
            q = {"pageSize": "300", "mask.fieldPaths": "__name__"}
            if page:
                q["pageToken"] = page
            data = self._api("GET", f"{self.base}/{collection}?{urllib.parse.urlencode(q)}")
            ids += [d["name"].rsplit("/", 1)[1] for d in data.get("documents", [])]
            page = data.get("nextPageToken", "")
            if not page:
                return ids

    def get(self, path: str) -> dict | None:
        try:
            return self._api("GET", f"{self.base}/{path}")
        except FirebaseError as exc:
            if str(exc).startswith("NOT_FOUND"):
                return None
            raise


def _google_error(exc: urllib.error.HTTPError) -> str:
    try:
        data = json.loads(exc.read() or b"{}")
    except ValueError:
        data = {}
    finally:
        exc.close()
    if not isinstance(data, dict):
        data = {}
    if "error_description" in data or isinstance(data.get("error"), str):  # OAuth token endpoint
        detail = data.get("error_description") or data.get("error")
        return (f"Google rejected the key ({detail}). Generate a new private key in Firebase -> Project settings "
                "-> Service accounts and paste it again.")
    err = data.get("error") if isinstance(data.get("error"), dict) else {}
    status, message = err.get("status") or f"HTTP {exc.code}", err.get("message") or exc.reason
    hint = ""
    if "does not exist" in message or ("Firestore API" in message and "disabled" in message):
        hint = (" -- create the database first: Firebase console -> Firestore Database -> Create database "
                "(production mode), wait a minute, then try again.")
    return f"{status}: {message}{hint}"


# ------------------------------------------------------------------ what gets mirrored (allow-lists)

def user_doc(u: dict, settings: dict, now: float) -> dict:
    return {
        "username": u["username"], "display_name": u["display_name"], "email": u["email"], "role": u["role"],
        "plan": u["plan"] or "free", "plan_in_effect": plans.effective_plan(u, now),
        "premium_until": ts(u["plan_expires"]), "custom_dns": u["custom_dns"],
        "dns": plans.dns_for(u, settings, now), "enabled": bool(u["enabled"]),
        "locked": u["locked_until"] > now, "two_factor": bool(u["totp_enabled"]), "vpn_ip": u["vpn_ip"],
        "profile_serial": u["active_serial"], "profile_issued_at": ts(u["profile_issued_at"]),
        "last_login_at": ts(u["last_login_at"]), "created_at": ts(u["created_at"]),
    }


def settings_doc(settings: dict) -> dict:
    return {
        "portal_access": settings.get("portal_access", "admins"),
        "dns_free_preset": settings["dns_free_preset"], "dns_free": plans.plan_dns(settings, "free"),
        "dns_premium_preset": settings["dns_premium_preset"], "dns_premium": plans.plan_dns(settings, "premium"),
        "email_ready": mail.is_configured(settings), "smtp_host": settings["smtp_host"],
        "smtp_port": settings["smtp_port"], "smtp_security": settings["smtp_security"],
        "smtp_user": settings["smtp_user"], "mail_from_name": settings["mail_from_name"],
    }


def connection_doc(p: dict) -> tuple[dict, dict]:
    """(stable part, volatile counters) of a live VPN session."""
    stable = {"username": p["username"], "endpoint": p["endpoint"], "address": p["address"], "suite": p["suite"],
              "encryption": describe_suite(p["suite"] or ""), "key_alg": p["key_alg"],
              "connected_since": ts(p["connected_since"])}
    volatile = {"last_handshake": ts(p["last_handshake"]), "rx_bytes": int(p["rx_bytes"] or 0),
                "tx_bytes": int(p["tx_bytes"] or 0), "updated_at": ts(p["updated_at"])}
    return stable, volatile


def audit_doc(a: dict) -> dict:
    return {"id": a["id"], "ts": ts(a["ts"]), "actor": a["actor"] or "", "ip": a["ip"] or "",
            "action": a["action"], "detail": a["detail"] or ""}


def _digest(fields: dict) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True, default=repr).encode()).hexdigest()


# ------------------------------------------------------------------ the mirror

class Mirror:
    def __init__(self, store, key_path: str, settings_fn, info: dict, endpoint: str = FIRESTORE,
                 token_uri: str = TOKEN_URI):
        self.store, self.key_path, self.settings_fn, self.info = store, key_path, settings_fn, info
        self.endpoint, self.token_uri = endpoint, token_uri
        self.lock = threading.Lock()
        self._client: Client | None = None
        self._client_endpoint = ""
        self._reset_state()
        self.last_ok = 0.0
        self.last_error = ""
        self.writes_total = 0

    def _reset_state(self) -> None:
        self.sent: dict[str, str] = {}               # path -> digest of what Firestore holds
        self.volatile_at: dict[str, float] = {}      # path -> last write of volatile fields
        self.reconciled = False

    # ---------------------------------------------------------- configuration
    def key(self) -> dict | None:
        try:
            return load_key(self.key_path)
        except FirebaseError:
            return None

    def enabled(self) -> bool:
        return self.settings_fn().get("firebase_enabled") == "1" and os.path.exists(self.key_path)

    def client(self) -> Client:
        key = load_key(self.key_path)
        if key is None:
            raise FirebaseError("no service-account key saved")
        if self._client is None or (self._client.key, self._client_endpoint, self._client.token_uri) != \
                (key, self.endpoint, self.token_uri):
            self._client = Client(key, self.endpoint, token_uri=self.token_uri)
            self._client_endpoint = self.endpoint
            if self.settings_fn().get("firebase_project") != key["project_id"]:
                # A different project: start over (full upload, audit backlog included).
                self.store.set_settings({"firebase_project": key["project_id"], "firebase_audit_id": "0"})
            self._reset_state()
        return self._client

    def connect(self, key: dict) -> int:
        """Check the key with Google, save it, switch the mirror on and upload everything.

        A key Google rejects is not saved.  If the key is fine but Firestore is not ready yet (no database
        created), the key is kept and the error raised; the background loop keeps retrying.
        """
        with self.lock:
            Client(key, self.endpoint, token_uri=self.token_uri).token()
            save_key(self.key_path, key)
            self.store.set_settings({"firebase_enabled": "1"})
            self._client = None
        return self.sync_once(force=True)

    def status(self) -> dict:
        key = self.key()
        return {"configured": key is not None, "enabled": self.enabled(), "project": key and key["project_id"],
                "account": key and key["client_email"], "last_ok": self.last_ok, "last_error": self.last_error,
                "writes": self.writes_total}

    # ---------------------------------------------------------- one sync pass
    def sync_once(self, force: bool = False) -> int:
        """Push everything that changed since the last pass; returns the number of writes."""
        with self.lock:
            try:
                n = self._sync(force)
            except FirebaseError as exc:
                if str(exc) != self.last_error:
                    log.warning("Firebase sync failed: %s", exc)
                self.last_error = str(exc)
                raise
            except Exception as exc:  # noqa: BLE001 -- never kill the portal over the mirror
                log.exception("Firebase sync crashed")
                self.last_error = f"internal error: {exc}"
                raise FirebaseError(self.last_error) from None
            if self.last_error or not self.last_ok:
                log.info("Firebase sync OK (project %s)", self._client.project)
            self.last_ok, self.last_error = time.time(), ""
            self.writes_total += n
            return n

    def _sync(self, force: bool) -> int:
        client = self.client()
        now = time.time()
        if force:
            self._reset_state()
        if not self.reconciled:  # learn what is already there so stale documents get deleted
            for coll in MIRRORED_COLLECTIONS:
                for doc_id in client.list_ids(coll):
                    self.sent.setdefault(f"{coll}/{doc_id}", "?")
            self.reconciled = True

        settings = self.settings_fn()
        users = self.store.users()
        peers = self.store.peers()
        heartbeat = self.store.server_heartbeat()
        want: dict[str, dict] = {}
        volatile: dict[str, dict] = {}
        for u in users:
            want[f"users/{u['username'].lower()}"] = user_doc(u, settings, now)
        for p in peers:
            stable, vol = connection_doc(p)
            want[f"connections/{p['username'].lower()}"] = stable
            volatile[f"connections/{p['username'].lower()}"] = vol
        want["settings/portal"] = settings_doc(settings)
        want["status/server"] = {
            "online": now - heartbeat < 10, "connected": len(peers), "users": len(users),
            "administrators": sum(u["role"] == "admin" for u in users),
            "premium": sum(plans.effective_plan(u, now) == "premium" for u in users),
            "issuer": self.info.get("issuer", ""), "server_name": self.info.get("server_name", ""),
            "endpoint": self.info.get("endpoint", ""), "subnet": self.info.get("subnet", ""),
            "portal_version": __version__}
        volatile["status/server"] = {"heartbeat": ts(heartbeat), "updated_at": Timestamp(now)}

        writes, new_sent, new_vol = [], {}, {}
        for path, fields in want.items():
            digest = _digest(fields)
            stale = now - self.volatile_at.get(path, 0) >= TRAFFIC_INTERVAL
            if self.sent.get(path) != digest or (path in volatile and stale):
                writes.append(client.update(path, {**fields, **volatile.get(path, {})}))
                new_vol[path] = now
            new_sent[path] = digest
        for path in self.sent:
            if path not in want and path.split("/")[0] in MIRRORED_COLLECTIONS:
                writes.append(client.delete(path))

        audit_from = int(settings.get("firebase_audit_id") or 0)
        rows = self.store.audit_after(audit_from, AUDIT_PER_SYNC)
        writes += [client.update(f"audit/{a['id']:010d}", audit_doc(a)) for a in rows]

        if writes:
            client.commit(writes)
        self.sent = new_sent
        self.volatile_at = {**{p: t for p, t in self.volatile_at.items() if p in new_sent}, **new_vol}
        if rows:
            self.store.set_settings({"firebase_audit_id": str(rows[-1]["id"])})
        return len(writes)

    # ---------------------------------------------------------- background loop
    def run(self, stop: threading.Event) -> None:
        delay = SYNC_INTERVAL
        while not stop.wait(delay):
            if not self.enabled():
                delay = SYNC_INTERVAL
                continue
            try:
                self.sync_once()
                delay = SYNC_INTERVAL
            except FirebaseError:
                delay = min(MAX_BACKOFF, delay * 2)
