"""Local control channel between the ShieldsVPN tray app and the browser extension's native-messaging host.

The tray app (winui.py, running elevated) listens on 127.0.0.1 on a random port.  The port and a random 256-bit
token are written to ``%LOCALAPPDATA%\\pqvpn\\tray-control.json``, which only this Windows user (and administrators)
can read.  The native-messaging host (native_host.py), started by the browser as the same user, reads that file and
sends one JSON line per connection: ``{"token": ..., "cmd": ...}``, answered by one JSON line.

Why it is safe to expose: it listens on loopback only; every request needs the token, compared in constant time; a
web page cannot read the file, and the protocol is a raw JSON line, not HTTP; requests are size- and time-limited;
and only three commands exist (status, connect, disconnect) -- nothing that reveals keys, profiles or settings.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import secrets
import socket
from typing import Callable

FILE = "tray-control.json"
COMMANDS = ("status", "connect", "disconnect")
MAX_LINE = 4096
MAX_ANSWER = 64 * 1024
TIMEOUT = 5.0


class ControlServer:
    """Runs on the tray app's asyncio loop.  ``handler(cmd)`` returns the answer fields (called on the loop)."""

    def __init__(self, handler: Callable[[str], dict], path: str, extra: dict | None = None):
        self.handler, self.path, self.extra = handler, path, dict(extra or {})
        self.token = secrets.token_urlsafe(32)
        self.server: asyncio.Server | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._client, "127.0.0.1", 0, limit=MAX_LINE)
        port = self.server.sockets[0].getsockname()[1]
        _write_private(self.path, json.dumps({**self.extra, "port": port, "token": self.token, "pid": os.getpid()}))
        return port

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), TIMEOUT)
            msg = json.loads(line.decode("utf-8"))
            token = msg.get("token") if isinstance(msg, dict) else None
            if not isinstance(token, str) or not hmac.compare_digest(token.encode(), self.token.encode()):
                answer = {"ok": False, "error": "unauthorized"}
            elif msg.get("cmd") not in COMMANDS:
                answer = {"ok": False, "error": "unknown command"}
            else:
                answer = {"ok": True, **self.handler(msg["cmd"])}
            writer.write(json.dumps(answer).encode() + b"\n")
            await asyncio.wait_for(writer.drain(), TIMEOUT)
        except (asyncio.TimeoutError, asyncio.LimitOverrunError, ValueError, UnicodeDecodeError, ConnectionError):
            pass  # oversized, slow or malformed: just hang up
        finally:
            writer.close()

    def close(self) -> None:
        if self.server is not None:
            self.server.close()
        info = read_info(self.path)  # remove the file only if it is still ours (another instance may have replaced it)
        if info is not None and info.get("token") == self.token:
            try:
                os.remove(self.path)  # after the file was closed: Windows refuses to delete an open file
            except OSError:
                pass


def _write_private(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def read_info(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            info = json.load(f)
        return info if isinstance(info, dict) and isinstance(info.get("port"), int) else None
    except (OSError, ValueError):
        return None


def request(cmd: str, path: str, timeout: float = TIMEOUT) -> dict:
    """One command to the running tray app.  ``{"running": False}`` when it is not running."""
    info = read_info(path)
    if info is None or not 0 < info["port"] < 65536:
        return {"ok": True, "running": False}
    try:
        with socket.create_connection(("127.0.0.1", info["port"]), timeout) as s:
            s.sendall(json.dumps({"token": str(info.get("token", "")), "cmd": cmd}).encode() + b"\n")
            data = b""
            while not data.endswith(b"\n") and len(data) <= MAX_ANSWER:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return {"ok": True, "running": False}  # stale file: the tray app is gone
    try:
        answer = json.loads(data.decode("utf-8")) if len(data) <= MAX_ANSWER else None
    except (UnicodeDecodeError, ValueError):
        answer = None
    if not isinstance(answer, dict):
        return {"ok": False, "error": "the ShieldsVPN app sent an invalid answer"}
    return {"running": True, **answer} if answer.get("ok") else answer
