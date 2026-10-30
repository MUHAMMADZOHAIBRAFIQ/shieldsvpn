"""SQLite persistence shared by the portal (writer) and the VPN server (reader +
live-status writer).  WAL mode lets both processes work concurrently.

Keep the database on a local filesystem (not a network/9p mount): SQLite's
locking relies on it.
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import time
from contextlib import contextmanager

from . import auth

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    vpn_ip TEXT UNIQUE,
    active_serial TEXT,
    profile_issued_at INTEGER,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER,
    email TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    plan_expires INTEGER,
    custom_dns TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    pending_2fa INTEGER NOT NULL DEFAULT 0,
    pending_totp_secret TEXT,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor TEXT,
    ip TEXT,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS peers (
    username TEXT PRIMARY KEY COLLATE NOCASE,
    endpoint TEXT,
    address TEXT,
    suite TEXT,
    key_alg TEXT,
    connected_since INTEGER,
    last_handshake INTEGER,
    rx_bytes INTEGER,
    tx_bytes INTEGER,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,
    ip TEXT
);
-- Browsers that signed in successfully before (OWASP "device cookies").  Failed sign-ins from a known
-- device lock only that device; failures from unknown clients lock the account for unknown clients only
-- (users.failed_logins / locked_until).  So nobody can lock an owner out of their usual browser.
CREATE TABLE IF NOT EXISTS devices (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_used INTEGER NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
);
-- Phones and PCs that enrolled themselves through the app API (devices.py).  Each has its own certificate
-- (subject "d-..."), so the VPN server keeps one peer per device.  user_id is NULL for anonymous Free devices
-- and set while someone is signed in on the device.  known_user_id remembers the last account signed in
-- here, so failed sign-ins from that device lock only the device (same idea as the browser "devices" table).
CREATE TABLE IF NOT EXISTS vpn_devices (
    id INTEGER PRIMARY KEY,
    subject TEXT NOT NULL UNIQUE COLLATE NOCASE,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    known_user_id INTEGER,
    platform TEXT NOT NULL,
    vpn_ip TEXT UNIQUE,
    active_serial TEXT,
    cert_expires INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    free_until INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    enroll_ip TEXT
);
-- One row per "watch an ad for free time" attempt.  The nonce is stored hashed; granted_at is set once
-- (single use) and provider_ref (the ad network's transaction id) is unique, so a replayed callback grants nothing.
CREATE TABLE IF NOT EXISTS reward_grants (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES vpn_devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    nonce_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    granted_at INTEGER,
    provider_ref TEXT UNIQUE
);
-- One-time links to Paddle's checkout (payments.py): the transaction was created by the portal for this account.
CREATE TABLE IF NOT EXISTS pay_links (
    code_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    txn_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    completed_at INTEGER
);
-- Payments seen at the provider (receipts stay with Paddle, the merchant of record); never card data.
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_ref TEXT NOT NULL UNIQUE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    amount TEXT,
    currency TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
-- Google Play subscription purchases (play.py), checked with Google's API.  One account per purchase token; replaced
-- = superseded by a newer token (plan change or re-signup).  Tokens are never logged.
CREATE TABLE IF NOT EXISTS play_purchases (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL,
    base_plan TEXT,
    state TEXT NOT NULL,
    expires INTEGER,
    test INTEGER NOT NULL DEFAULT 0,
    replaced INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""

# Columns added after the first release: (name, definition) -- applied to older databases on open.
# email_verified defaults to 1 so every admin-created account stays usable; self-service sign-ups set it to 0
# until the emailed code is entered.
USER_COLUMNS = [("email", "TEXT"), ("plan", "TEXT NOT NULL DEFAULT 'free'"), ("plan_expires", "INTEGER"),
                ("custom_dns", "TEXT"), ("email_verified", "INTEGER NOT NULL DEFAULT 1"),
                ("paddle_customer_id", "TEXT"), ("paddle_subscription_id", "TEXT")]
INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (email COLLATE NOCASE) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS password_resets_user ON password_resets (user_id, created_at);
CREATE INDEX IF NOT EXISTS devices_user ON devices (user_id, last_used);
CREATE INDEX IF NOT EXISTS vpn_devices_user ON vpn_devices (user_id);
CREATE INDEX IF NOT EXISTS vpn_devices_enroll ON vpn_devices (enroll_ip, created_at);
CREATE INDEX IF NOT EXISTS reward_grants_device ON reward_grants (device_id, granted_at);
CREATE INDEX IF NOT EXISTS play_purchases_due ON play_purchases (replaced, expires);
"""
VPN_DEVICE_FIELDS = {"user_id", "known_user_id", "active_serial", "cert_expires", "enabled", "free_until",
                     "failed_logins", "locked_until", "last_seen", "token_hash"}
MAX_DEVICES_PER_USER = 20


class Store:
    def __init__(self, path: str):
        self.path = path
        with self._db() as db:
            db.executescript(SCHEMA)
            db.execute("BEGIN IMMEDIATE")  # the portal and the VPN server may both be upgrading the file
            have = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
            for name, definition in USER_COLUMNS:
                if name not in have:
                    db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
            db.execute("COMMIT")
            db.executescript(INDEXES)

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA busy_timeout=5000")
            yield con
        finally:
            con.close()

    def _one(self, sql: str, args=()) -> dict | None:
        with self._db() as db:
            row = db.execute(sql, args).fetchone()
            return dict(row) if row else None

    def _all(self, sql: str, args=()) -> list[dict]:
        with self._db() as db:
            return [dict(r) for r in db.execute(sql, args).fetchall()]

    def _exec(self, sql: str, args=()) -> int:
        with self._db() as db:
            return db.execute(sql, args).rowcount

    # -------------------------------------------------------------- users
    def create_user(self, username: str, role: str, password: str, display_name: str = "",
                    vpn_ip: str | None = None, must_change: bool = True) -> int:
        password_hash = auth.hash_password(password)  # before the write lock: scrypt takes a while
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                # Never reuse a deleted account's id.  Payments name accounts by id (Paddle custom_data, the Google
                # Play account reference), so a reused id would inherit someone else's running subscription.
                # SQLite reuses the highest rowid after it is deleted; users_id_floor remembers deleted ids.
                floor = db.execute("SELECT value FROM meta WHERE key = 'users_id_floor'").fetchone()
                top = db.execute("SELECT COALESCE(MAX(id), 0) FROM users").fetchone()[0]
                uid = max(top, int(floor[0]) if floor else 0) + 1
                db.execute(
                    "INSERT INTO users (id, username, display_name, role, password_hash, must_change_password, vpn_ip,"
                    " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (uid, username, display_name, role, password_hash, int(must_change), vpn_ip, int(time.time())))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            return uid

    def user(self, user_id: int) -> dict | None:
        return self._one("SELECT * FROM users WHERE id = ?", (user_id,))

    def user_by_name(self, username: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE username = ?", (username,))

    def user_by_email(self, email: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,))

    def users(self) -> list[dict]:
        return self._all("SELECT * FROM users ORDER BY role, username")

    def update_user(self, user_id: int, **fields) -> None:
        allowed = {"display_name", "role", "password_hash", "must_change_password", "totp_secret", "totp_enabled",
                   "totp_last_step", "enabled", "vpn_ip", "active_serial", "profile_issued_at", "failed_logins",
                   "locked_until", "last_login_at", "email", "plan", "plan_expires", "custom_dns", "email_verified",
                   "paddle_customer_id", "paddle_subscription_id"}
        if not fields or set(fields) - allowed:
            raise ValueError(f"bad fields {set(fields) - allowed}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE users SET {cols} WHERE id = ?", (*fields.values(), user_id))

    def delete_user(self, user_id: int) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            # The account's app devices become anonymous Free devices with no time left (ON DELETE SET NULL),
            # so deleting someone still ends their VPN access within one status interval.
            db.execute("UPDATE vpn_devices SET free_until = 0 WHERE user_id = ?", (user_id,))
            db.execute("INSERT INTO meta (key, value) VALUES ('users_id_floor', ?) ON CONFLICT(key) DO UPDATE SET"
                       " value = CAST(MAX(CAST(meta.value AS INTEGER), CAST(excluded.value AS INTEGER)) AS TEXT)",
                       (str(user_id),))  # see create_user: this id is never handed out again
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.execute("COMMIT")

    def unlink_vpn_devices(self, user_id: int) -> int:
        """Sign the account out of every app device (they become Free devices again).  Returns how many."""
        return self._exec("UPDATE vpn_devices SET user_id = NULL WHERE user_id = ?", (user_id,))

    def allocate_ip(self, subnet: str, reserved: set[str]) -> str:
        with self._db() as db:
            return self._free_ip(db, subnet, reserved)

    @staticmethod
    def _free_ip(db, subnet: str, reserved: set[str]) -> str:
        net = ipaddress.ip_network(subnet)
        used = {r[0] for r in db.execute("SELECT vpn_ip FROM users WHERE vpn_ip IS NOT NULL UNION "
                                         "SELECT vpn_ip FROM vpn_devices WHERE vpn_ip IS NOT NULL")} | reserved
        for host in net.hosts():
            if str(host) not in used:
                return str(host)
        raise ValueError(f"no free addresses left in {subnet}")

    # -------------------------------------------------------------- app-enrolled VPN devices (devices.py)
    def create_vpn_device(self, subject: str, token_hash: str, platform: str, subnet: str, reserved: set[str],
                          ip: str) -> dict:
        """Insert a device with a freshly allocated tunnel address (one transaction, so two parallel
        enrollments cannot get the same address)."""
        now = int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                vpn_ip = self._free_ip(db, subnet, reserved)
                cur = db.execute("INSERT INTO vpn_devices (subject, token_hash, platform, vpn_ip, created_at,"
                                 " last_seen, enroll_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                 (subject, token_hash, platform, vpn_ip, now, now, ip))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return self.vpn_device(cur.lastrowid)

    def vpn_device(self, device_id: int) -> dict | None:
        return self._one("SELECT * FROM vpn_devices WHERE id = ?", (device_id,))

    def vpn_device_by_subject(self, subject: str) -> dict | None:
        return self._one("SELECT * FROM vpn_devices WHERE subject = ?", (subject,))

    def vpn_device_by_token(self, token: str) -> dict | None:
        return self._one("SELECT * FROM vpn_devices WHERE token_hash = ?", (auth.token_hash(token),))

    def vpn_devices(self, user_id: int | None = None, limit: int = 500) -> list[dict]:
        if user_id is None:
            return self._all("SELECT * FROM vpn_devices ORDER BY last_seen DESC LIMIT ?", (limit,))
        return self._all("SELECT * FROM vpn_devices WHERE user_id = ? ORDER BY last_seen DESC", (user_id,))

    def update_vpn_device(self, device_id: int, **fields) -> None:
        if not fields or set(fields) - VPN_DEVICE_FIELDS:
            raise ValueError(f"bad fields {set(fields) - VPN_DEVICE_FIELDS}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE vpn_devices SET {cols} WHERE id = ?", (*fields.values(), device_id))

    def delete_vpn_device(self, device_id: int) -> None:
        self._exec("DELETE FROM vpn_devices WHERE id = ?", (device_id,))

    def enrollments_since(self, ip: str, since: int) -> int:
        return self._one("SELECT COUNT(*) AS n FROM vpn_devices WHERE enroll_ip = ? AND created_at >= ?",
                         (ip, since))["n"]

    def device_counts(self) -> dict:
        row = self._one("SELECT COUNT(*) AS total, SUM(user_id IS NULL) AS anonymous FROM vpn_devices")
        return {"total": row["total"] or 0, "anonymous": row["anonymous"] or 0}

    def touch_vpn_devices(self, subjects: list[str], now: int) -> None:
        if subjects:
            with self._db() as db:
                db.executemany("UPDATE vpn_devices SET last_seen = ? WHERE subject = ?", [(now, s) for s in subjects])

    def purge_anonymous_devices(self, max_age: int) -> int:
        """Forget anonymous devices unseen for ``max_age`` seconds; their tunnel addresses become free again."""
        return self._exec("DELETE FROM vpn_devices WHERE user_id IS NULL AND last_seen < ?",
                          (int(time.time()) - max_age,))

    def add_free_time(self, device_id: int, seconds: int, now: int) -> int:
        """Extend free time atomically (from now, or from the end of time already granted); return the new end."""
        with self._db() as db:
            db.execute("UPDATE vpn_devices SET free_until = MAX(free_until, ?) + ? WHERE id = ?",
                       (now, seconds, device_id))
            return db.execute("SELECT free_until FROM vpn_devices WHERE id = ?", (device_id,)).fetchone()[0]

    # -------------------------------------------------------------- ad rewards
    def create_reward(self, device_id: int, kind: str, nonce_hash: str) -> int:
        with self._db() as db:
            return db.execute("INSERT INTO reward_grants (device_id, kind, nonce_hash, created_at) VALUES (?, ?, ?, ?)",
                              (device_id, kind, nonce_hash, int(time.time()))).lastrowid

    def reward_by_nonce(self, nonce_hash: str) -> dict | None:
        return self._one("SELECT * FROM reward_grants WHERE nonce_hash = ?", (nonce_hash,))

    def start_reward(self, reward_id: int, now: int) -> None:
        self._exec("UPDATE reward_grants SET started_at = ? WHERE id = ? AND started_at IS NULL", (now, reward_id))

    def claim_reward(self, reward_id: int, now: int, provider_ref: str | None = None) -> bool:
        """Mark granted; False if it was already granted or the provider reference was used before (single use)."""
        try:
            return self._exec("UPDATE reward_grants SET granted_at = ?, provider_ref = ? WHERE id = ? AND"
                              " granted_at IS NULL", (now, provider_ref, reward_id)) == 1
        except sqlite3.IntegrityError:  # provider_ref already used by another grant: a replayed callback
            return False

    def rewards_granted_since(self, device_id: int, since: int) -> int:
        return self._one("SELECT COUNT(*) AS n FROM reward_grants WHERE device_id = ? AND granted_at >= ?",
                         (device_id, since))["n"]

    def purge_rewards(self, older_than: int) -> None:
        self._exec("DELETE FROM reward_grants WHERE created_at < ?", (int(time.time()) - older_than,))

    # -------------------------------------------------------------- payments (payments.py)
    def create_pay_link(self, code_hash: str, user_id: int, txn_id: str, ttl: int) -> None:
        now = int(time.time())
        self._exec("INSERT INTO pay_links (code_hash, user_id, txn_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                   (code_hash, user_id, txn_id, now, now + ttl))

    def pay_link(self, code_hash: str) -> dict | None:
        return self._one("SELECT * FROM pay_links WHERE code_hash = ?", (code_hash,))

    def open_pay_links(self, user_id: int, since: float) -> list[dict]:
        return self._all("SELECT * FROM pay_links WHERE user_id = ? AND completed_at IS NULL AND created_at >= ?"
                         " ORDER BY created_at DESC LIMIT 10", (user_id, int(since)))

    def complete_pay_link(self, code_hash: str) -> None:
        self._exec("UPDATE pay_links SET completed_at = ? WHERE code_hash = ? AND completed_at IS NULL",
                   (int(time.time()), code_hash))

    def record_payment(self, provider: str, ref: str, user_id: int, status: str, amount: str, currency: str) -> None:
        now = int(time.time())
        self._exec("INSERT INTO payments (provider, provider_ref, user_id, status, amount, currency, created_at,"
                   " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(provider_ref) DO UPDATE SET"
                   " status = excluded.status, updated_at = excluded.updated_at",
                   (provider, ref, user_id, status, amount, currency, now, now))

    def payments(self, user_id: int | None = None, limit: int = 100) -> list[dict]:
        if user_id is None:
            return self._all("SELECT * FROM payments ORDER BY created_at DESC LIMIT ?", (limit,))
        return self._all("SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT ?", (user_id, limit))

    # -------------------------------------------------------------- Google Play purchases (play.py)
    def play_purchase(self, token: str) -> dict | None:
        return self._one("SELECT * FROM play_purchases WHERE token = ?", (token,))

    def save_play_purchase(self, token: str, user_id: int, product_id: str, base_plan: str, state: str,
                           expires: int, test: bool) -> None:
        now = int(time.time())
        self._exec("INSERT INTO play_purchases (token, user_id, product_id, base_plan, state, expires, test, created_at,"
                   " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(token) DO UPDATE SET"
                   " state = excluded.state, expires = excluded.expires, base_plan = excluded.base_plan,"
                   " updated_at = excluded.updated_at WHERE play_purchases.user_id = excluded.user_id",
                   (token, user_id, product_id, base_plan, state, expires, int(test), now, now))

    def replace_play_purchase(self, token: str, user_id: int) -> None:
        self._exec("UPDATE play_purchases SET replaced = 1, updated_at = ? WHERE token = ? AND user_id = ?",
                   (int(time.time()), token, user_id))

    def play_purchases_due(self, ending_before: float) -> list[dict]:
        # Purchases that ended more than 60 days ago are left alone: Google stops answering for them.
        return self._all("SELECT * FROM play_purchases WHERE replaced = 0 AND expires < ? AND expires > ? AND state"
                         " NOT IN ('SUBSCRIPTION_STATE_EXPIRED', 'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED')"
                         " ORDER BY expires LIMIT 500", (int(ending_before), int(time.time()) - 60 * 86400))

    def users_with_subscriptions(self, ending_before: float) -> list[dict]:
        return self._all("SELECT * FROM users WHERE paddle_subscription_id IS NOT NULL AND"
                         " (plan_expires IS NULL OR plan_expires < ?)", (int(ending_before),))

    # -------------------------------------------------------------- sessions
    def create_session(self, user_id: int, ip: str, user_agent: str, pending_2fa: bool) -> tuple[str, str]:
        token, csrf, now = auth.new_token(), auth.new_token(), int(time.time())
        self._exec("INSERT INTO sessions (token_hash, user_id, csrf, pending_2fa, created_at, last_seen, ip,"
                   " user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (auth.token_hash(token), user_id, csrf, int(pending_2fa), now, now, ip, user_agent[:200]))
        return token, csrf

    def session(self, token: str, idle: int, absolute: int) -> dict | None:
        th, now = auth.token_hash(token), int(time.time())
        s = self._one("SELECT * FROM sessions WHERE token_hash = ?", (th,))
        if s is None:
            return None
        if now - s["last_seen"] > idle or now - s["created_at"] > absolute:
            self._exec("DELETE FROM sessions WHERE token_hash = ?", (th,))
            return None
        if now - s["last_seen"] > 30:
            self._exec("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, th))
        return s

    def set_session(self, token: str, **fields) -> None:
        if set(fields) - {"pending_totp_secret"}:
            raise ValueError("bad session field")
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE sessions SET {cols} WHERE token_hash = ?", (*fields.values(), auth.token_hash(token)))

    def delete_session(self, token: str) -> None:
        self._exec("DELETE FROM sessions WHERE token_hash = ?", (auth.token_hash(token),))

    def delete_user_sessions(self, user_id: int, keep_token: str | None = None) -> None:
        keep = auth.token_hash(keep_token) if keep_token else ""
        self._exec("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, keep))

    def session_count(self, user_id: int) -> int:
        return self._one("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", (user_id,))["n"]

    def purge_sessions(self, idle: int, absolute: int) -> None:
        now = int(time.time())
        self._exec("DELETE FROM sessions WHERE last_seen < ? OR created_at < ?", (now - idle, now - absolute))

    # -------------------------------------------------------------- trusted devices (lockout scoping)
    def create_device(self, user_id: int) -> str:
        token, now = auth.new_token(), int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO devices (token_hash, user_id, created_at, last_used) VALUES (?, ?, ?, ?)",
                       (auth.token_hash(token), user_id, now, now))
            db.execute("DELETE FROM devices WHERE user_id = ? AND token_hash NOT IN (SELECT token_hash FROM devices"
                       " WHERE user_id = ? ORDER BY last_used DESC LIMIT ?)", (user_id, user_id, MAX_DEVICES_PER_USER))
            db.execute("COMMIT")
        return token

    def device(self, token: str, user_id: int, max_age: int) -> dict | None:
        """The device record if ``token`` belongs to ``user_id`` and was used within ``max_age`` seconds."""
        d = self._one("SELECT * FROM devices WHERE token_hash = ? AND user_id = ?", (auth.token_hash(token), user_id))
        return d if d and d["last_used"] > time.time() - max_age else None

    def update_device(self, token_hash: str, **fields) -> None:
        if not fields or set(fields) - {"last_used", "failed_logins", "locked_until"}:
            raise ValueError("bad device field")
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE devices SET {cols} WHERE token_hash = ?", (*fields.values(), token_hash))

    def unlock_devices(self, user_id: int) -> None:
        self._exec("UPDATE devices SET failed_logins = 0, locked_until = 0 WHERE user_id = ?", (user_id,))

    def purge_devices(self, max_age: int) -> None:
        self._exec("DELETE FROM devices WHERE last_used < ?", (int(time.time()) - max_age,))

    # -------------------------------------------------------------- settings (admin-editable)
    def settings(self, defaults: dict | None = None) -> dict:
        rows = {r["key"]: r["value"] for r in self._all("SELECT key, value FROM settings")}
        return {**(defaults or {}), **rows}

    def set_settings(self, values: dict) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                           [(k, str(v)) for k, v in values.items()])
            db.execute("COMMIT")

    # -------------------------------------------------------------- password resets (emailed codes)
    def create_reset(self, user_id: int, code_hash: str, ttl: int, ip: str) -> None:
        """A new code supersedes every earlier unused one for the account."""
        now = int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (user_id,))
            db.execute("INSERT INTO password_resets (user_id, code_hash, created_at, expires_at, ip)"
                       " VALUES (?, ?, ?, ?, ?)", (user_id, code_hash, now, now + ttl, ip))
            db.execute("COMMIT")

    def resets_since(self, user_id: int, since: int) -> list[dict]:
        return self._all("SELECT * FROM password_resets WHERE user_id = ? AND created_at >= ? ORDER BY id DESC",
                         (user_id, since))

    def active_reset(self, user_id: int) -> dict | None:
        return self._one("SELECT * FROM password_resets WHERE user_id = ? AND used = 0 AND expires_at > ?"
                         " ORDER BY id DESC LIMIT 1", (user_id, int(time.time())))

    def reset_failed(self, reset_id: int, max_attempts: int) -> None:
        self._exec("UPDATE password_resets SET attempts = attempts + 1,"
                   " used = CASE WHEN attempts + 1 >= ? THEN 1 ELSE used END WHERE id = ?", (max_attempts, reset_id))

    def consume_reset(self, reset_id: int) -> bool:
        """Mark used; False if another request consumed it first (single use)."""
        return self._exec("UPDATE password_resets SET used = 1 WHERE id = ? AND used = 0", (reset_id,)) == 1

    def purge_resets(self, older_than: int) -> None:
        self._exec("DELETE FROM password_resets WHERE created_at < ?", (int(time.time()) - older_than,))

    # -------------------------------------------------------------- audit
    def audit(self, action: str, actor: str = "", ip: str = "", detail: str = "") -> None:
        self._exec("INSERT INTO audit (ts, actor, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
                   (int(time.time()), actor, ip, action, detail[:500]))

    def audit_after(self, last_id: int, limit: int) -> list[dict]:
        return self._all("SELECT * FROM audit WHERE id > ? ORDER BY id LIMIT ?", (last_id, limit))

    def recent_audit(self, limit: int = 50) -> list[dict]:
        return self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    # -------------------------------------------------------------- live VPN status (written by the server)
    def publish_peers(self, rows: list[dict]) -> None:
        now = int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM peers")
            db.executemany(
                "INSERT INTO peers (username, endpoint, address, suite, key_alg, connected_since, last_handshake,"
                " rx_bytes, tx_bytes, updated_at) VALUES (:username, :endpoint, :address, :suite, :key_alg,"
                " :connected_since, :last_handshake, :rx_bytes, :tx_bytes, " + str(now) + ")", rows)
            db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('server_heartbeat', ?)", (str(now),))
            db.execute("COMMIT")

    def peers(self) -> list[dict]:
        return self._all("SELECT * FROM peers ORDER BY username")

    def server_heartbeat(self) -> int:
        row = self._one("SELECT value FROM meta WHERE key = 'server_heartbeat'")
        return int(row["value"]) if row else 0


def secure_file(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
