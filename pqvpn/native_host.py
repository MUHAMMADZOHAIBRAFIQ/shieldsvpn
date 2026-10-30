"""Native-messaging host for the ShieldsVPN browser extension (Chrome, Edge, Brave, Opera, Chromium, Firefox).

Browsers start this program for the extension and talk to it over stdin/stdout.  Each message is a 32-bit length in
native byte order followed by UTF-8 JSON (Chrome native messaging / WebExtensions ``runtime.connectNative``).  The
host never touches keys, profiles or the network: it relays a fixed set of commands to the running ShieldsVPN tray
app over the local control channel (control.py), or starts the app.  The browser itself only lets the extension IDs
listed in the host manifest (``allowed_origins`` / ``allowed_extensions``) start it.

    python -m pqvpn browser-host install --chrome-id <extension id> [--firefox-id <id>] [--config client.toml]
    python -m pqvpn browser-host uninstall
"""

from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
from typing import BinaryIO, Callable

from . import control

HOST_NAME = "com.shieldsvpn.native"
MAX_MESSAGE = 64 * 1024
COMMANDS = ("status", "connect", "disconnect", "launch", "open")
CHROME_ID_RE = re.compile(r"^[a-p]{32}$")
FIREFOX_ID_RE = re.compile(r"^[A-Za-z0-9._@{}-]{3,80}$")
DEFAULT_FIREFOX_ID = "companion@shieldsvpn.app"
# Per-user registry keys where browsers look for native-messaging hosts (HKEY_CURRENT_USER, no admin needed).
# Opera and Vivaldi read Chrome's key.
CHROMIUM_KEYS = (r"Software\Google\Chrome\NativeMessagingHosts", r"Software\Microsoft\Edge\NativeMessagingHosts",
                 r"Software\Chromium\NativeMessagingHosts", r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts")
FIREFOX_KEY = r"Software\Mozilla\NativeMessagingHosts"


def app_dir() -> str:
    return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "pqvpn")


def control_path() -> str:
    return os.path.join(app_dir(), control.FILE)


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------ framing

def read_message(stream: BinaryIO) -> dict | None:
    """The next message, or None at end of input.  Raises ValueError for an oversized or malformed one."""
    header = stream.read(4)
    if len(header) < 4:
        return None
    (n,) = struct.unpack("=I", header)
    if n > MAX_MESSAGE:
        raise ValueError("message too large")
    body = stream.read(n)
    if len(body) < n:
        return None
    msg = json.loads(body.decode("utf-8"))
    if not isinstance(msg, dict):
        raise ValueError("expected a JSON object")
    return msg


def write_message(stream: BinaryIO, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


# ------------------------------------------------------------------ commands

def _config(info: dict | None) -> str | None:
    """The client profile to start the app with: the running app's, else the one chosen at install time."""
    candidates = [(info or {}).get("config")]
    try:
        with open(os.path.join(app_dir(), "native-host.json"), encoding="utf-8") as f:
            candidates.append(json.load(f).get("config"))
    except (OSError, ValueError, AttributeError):
        pass
    for c in candidates:
        if isinstance(c, str) and c.endswith(".toml") and os.path.isfile(c):
            return c
    return None


def _start(kind: str, config: str) -> None:
    """Start the tray app (it asks for Administrator through UAC) or the window app, detached from the browser."""
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen([pyw if os.path.exists(pyw) else exe, "-m", "pqvpn", kind, "-c", config], cwd=project_root(),
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=flags, close_fds=True)


def handle(msg: dict, path: str | None = None, starter: Callable[[str, str], None] = _start) -> dict:
    path = path or control_path()
    cmd = msg.get("cmd")
    if cmd not in COMMANDS:
        return {"ok": False, "error": "unknown command"}
    if cmd in ("status", "connect", "disconnect"):
        return control.request(cmd, path)
    status = control.request("status", path)
    config = _config(control.read_info(path))
    if config is None:
        return {"ok": False, "error": "no ShieldsVPN profile found on this PC; open the ShieldsVPN app once"}
    if cmd == "launch":
        if status.get("running"):
            return status
        starter("tray", config)
        return {"ok": True, "running": False, "starting": True}
    starter("app", config)  # "open": the window with Free time, sign-in and Pro
    return {"ok": True, **status}


def serve(stdin: BinaryIO, stdout: BinaryIO, path: str | None = None) -> int:
    while True:
        try:
            msg = read_message(stdin)
        except (ValueError, UnicodeDecodeError):
            write_message(stdout, {"ok": False, "error": "invalid message"})
            return 1
        if msg is None:
            return 0
        write_message(stdout, handle(msg, path))


def main(argv: list[str]) -> int:
    # argv[0] is the calling extension's origin (Chromium) or the manifest path (Firefox); the browser has already
    # checked it against the host manifest, so it is not used here.
    return serve(sys.stdin.buffer, sys.stdout.buffer)


# ------------------------------------------------------------------ installation (Windows, per user)

def _registry_set(key_path: str, value: str) -> None:
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path + "\\" + HOST_NAME) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, value)


def _registry_delete(key_path: str) -> None:
    import winreg
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path + "\\" + HOST_NAME)
    except FileNotFoundError:
        pass


def install(chrome_ids: list[str], firefox_id: str = DEFAULT_FIREFOX_ID, config: str | None = None,
            directory: str | None = None, registry_set: Callable[[str, str], None] = _registry_set) -> list[str]:
    """Write the host launcher and manifests and register them for every supported browser.  Returns the files."""
    if not chrome_ids and not firefox_id:
        raise ValueError("give at least one extension id")
    for cid in chrome_ids:
        if not CHROME_ID_RE.match(cid):
            raise ValueError(f"{cid!r} is not a Chrome/Edge extension id (32 letters a-p)")
    if firefox_id and not FIREFOX_ID_RE.match(firefox_id):
        raise ValueError(f"{firefox_id!r} is not a Firefox add-on id")
    if config is not None and not (config.endswith(".toml") and os.path.isfile(config)):
        raise ValueError(f"{config} is not a client profile (client.toml)")
    directory = os.path.abspath(directory or os.path.join(app_dir(), "native-host"))
    root, exe = project_root(), sys.executable
    for p in (root, exe, directory):
        if any(c in p for c in '%"^&|<>'):
            raise ValueError(f"cannot write a launcher for the path {p!r} (special characters)")
    os.makedirs(directory, exist_ok=True)
    launcher = os.path.join(directory, "shieldsvpn-native-host.bat")
    with open(launcher, "w", encoding="ascii", newline="\r\n") as f:
        f.write(f'@echo off\ncd /d "{root}"\n"{exe}" -m pqvpn native-host %*\n')
    files = [launcher]
    desc = "ShieldsVPN companion: status and connect / disconnect for the ShieldsVPN app"
    if chrome_ids:
        manifest = os.path.join(directory, f"{HOST_NAME}.chromium.json")
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({"name": HOST_NAME, "description": desc, "path": launcher, "type": "stdio",
                       "allowed_origins": [f"chrome-extension://{cid}/" for cid in chrome_ids]}, f, indent=2)
        files.append(manifest)
        for key in CHROMIUM_KEYS:
            registry_set(key, manifest)
    if firefox_id:
        manifest = os.path.join(directory, f"{HOST_NAME}.firefox.json")
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({"name": HOST_NAME, "description": desc, "path": launcher, "type": "stdio",
                       "allowed_extensions": [firefox_id]}, f, indent=2)
        files.append(manifest)
        registry_set(FIREFOX_KEY, manifest)
    if config is not None:
        settings = os.path.join(app_dir(), "native-host.json")
        os.makedirs(app_dir(), exist_ok=True)
        with open(settings, "w", encoding="utf-8") as f:
            json.dump({"config": os.path.abspath(config)}, f)
        files.append(settings)
    return files


def uninstall(registry_delete: Callable[[str], None] = _registry_delete) -> None:
    for key in (*CHROMIUM_KEYS, FIREFOX_KEY):
        registry_delete(key)
