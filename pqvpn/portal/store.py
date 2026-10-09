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
"""

# Columns added after the first release: (name, definition) -- applied to older databases on open.
USER_COLUMNS = [("email", "TEXT"), ("plan", "TEXT NOT NULL DEFAULT 'free'"), ("plan_expires", "INTEGER"),
                ("custom_dns", "TEXT")]
INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (email COLLATE NOCASE) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS password_resets_user ON password_resets (user_id, created_at);
CREATE INDEX IF NOT EXISTS devices_user ON devices (user_id, last_used);
"""
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
        with self._db() as db:
            cur = db.execute(
                "INSERT INTO users (username, display_name, role, password_hash, must_change_password, vpn_ip,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, display_name, role, auth.hash_password(password), int(must_change), vpn_ip,
                 int(time.time())))
            return cur.lastrowid

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
                   "locked_until", "last_login_at", "email", "plan", "plan_expires", "custom_dns"}
        if not fields or set(fields) - allowed:
            raise ValueError(f"bad fields {set(fields) - allowed}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        self._exec(f"UPDATE users SET {cols} WHERE id = ?", (*fields.values(), user_id))

    def delete_user(self, user_id: int) -> None:
        self._exec("DELETE FROM users WHERE id = ?", (user_id,))

    def allocate_ip(self, subnet: str, reserved: set[str]) -> str:
        net = ipaddress.ip_network(subnet)
        used = {u["vpn_ip"] for u in self._all("SELECT vpn_ip FROM users WHERE vpn_ip IS NOT NULL")} | reserved
        for host in net.hosts():
            if str(host) not in used:
                return str(host)
        raise ValueError(f"no free addresses left in {subnet}")

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
