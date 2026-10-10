"""ShieldsVPN desktop app: a simple one-tap "Tap to Connect" window.

A friendly front end for end users, built on the same client engine as the tray
app (``runner.run_client``): a big power button that connects/disconnects, a live
status, and the connection details.  Pure standard library (tkinter + ctypes).

Run it with::

    python -m pqvpn app -c client.toml

On Windows the VPN needs Administrator (to create the network adapter); the app
asks for it through UAC the moment you press Connect.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import queue
import sys
import threading
import time
import tkinter as tk

from .config import load_client
from .crypto.suites import describe_suite
from .runner import run_client

# -------------------------------------------------------------------- palette (matches the web/brand)
BG, CARD, LINE = "#0b1020", "#111a2e", "#1e293b"
INK, MUTED = "#e2e8f0", "#94a3b8"
BRAND, BRAND2 = "#6366f1", "#22d3ee"
GREEN, AMBER, RED, GREY = "#22c55e", "#f59e0b", "#ef4444", "#334155"

# state -> (accent colour, headline, sub-text)
STATES = {
    "disconnected": (GREY, "Tap to Connect", "You are not protected"),
    "connecting": (AMBER, "Connecting…", "Setting up your secure tunnel"),
    "reconnecting": (AMBER, "Reconnecting…", "The connection dropped; restoring it"),
    "connected": (GREEN, "Connected", "Post-quantum protection is on"),
    "error": (RED, "Not connected", "Could not connect — tap to retry"),
}


def _is_admin() -> bool:
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _relaunch_elevated(config_path: str) -> bool:
    """Ask Windows UAC to relaunch the app as Administrator, already connecting."""
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    exe = pyw if os.path.exists(pyw) else exe
    args = f'-m pqvpn app -c "{os.path.abspath(config_path)}" --connect'
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, _project_root(), 1)
    return (rc or 0) > 32


# -------------------------------------------------------------------- VPN engine (background thread)

class VpnController:
    """Runs the VPN client on an asyncio loop in a background thread; reports state via a callback."""

    def __init__(self, config_path: str, on_state):
        self.config_path = os.path.abspath(config_path)
        self.on_state = on_state
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, name="shieldsvpn-loop", daemon=True).start()
        self.future: asyncio.Future | None = None

    def busy(self) -> bool:
        return self.future is not None and not self.future.done()

    def connect(self) -> None:
        if self.busy():
            return
        try:
            cfg = load_client(self.config_path)  # re-read each time: picks up a new profile
        except Exception as exc:  # noqa: BLE001
            self.on_state("error", {"message": f"Could not read the profile: {exc}"})
            return
        self.on_state("connecting", {})
        self.future = asyncio.run_coroutine_threadsafe(self._run(cfg), self.loop)

    async def _run(self, cfg) -> None:
        try:
            await run_client(cfg, on_state=self.on_state)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 -- incl. SystemExit from the admin check
            self.on_state("error", {"message": str(exc) or type(exc).__name__})

    def disconnect(self, wait: float = 0) -> None:
        fut = self.future
        if fut is not None and not fut.done():
            fut.cancel()
            if wait:
                try:
                    fut.result(timeout=wait)
                except BaseException:  # noqa: BLE001
                    pass


# -------------------------------------------------------------------- the window

class ShieldsApp:
    DIAM = 220  # power-button diameter

    def __init__(self, root: tk.Tk, config_path: str, autoconnect: bool = False):
        self.root = root
        self.config_path = os.path.abspath(config_path)
        try:
            self.server_name = load_client(self.config_path).server_name
        except Exception:  # noqa: BLE001
            self.server_name = "ShieldsVPN"
        self.state, self.info, self.connected_at = "disconnected", {}, None
        self.events: queue.Queue = queue.Queue()
        self.ctl = VpnController(self.config_path, lambda s, i: self.events.put((s, i)))
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(80, self._pump)
        self.root.after(250, self._tick)
        if autoconnect:
            self.root.after(300, self._toggle)

    # ---------------------------------------------------------------- layout
    def _build(self) -> None:
        r = self.root
        r.title("ShieldsVPN")
        r.configure(bg=BG)
        r.geometry("400x660")
        r.resizable(False, False)
        try:
            r.call("tk", "scaling", 1.3)
        except tk.TclError:
            pass

        tk.Frame(r, bg=BG, height=18).pack()
        head = tk.Frame(r, bg=BG)
        head.pack(fill="x", padx=26)
        tk.Label(head, text="\U0001F6E1", bg=BG, fg=BRAND2, font=("Segoe UI Emoji", 20)).pack(side="left")
        tk.Label(head, text="Shields", bg=BG, fg=INK, font=("Segoe UI Semibold", 17)).pack(side="left", padx=(8, 0))
        tk.Label(head, text="VPN", bg=BG, fg=BRAND2, font=("Segoe UI Semibold", 17)).pack(side="left")

        self.sub = tk.Label(r, text="You are not protected", bg=BG, fg=MUTED, font=("Segoe UI", 10))
        self.sub.pack(pady=(2, 0))

        # the big circular button
        self.cv = tk.Canvas(r, width=self.DIAM + 60, height=self.DIAM + 60, bg=BG, highlightthickness=0)
        self.cv.pack(pady=(22, 6))
        self.cv.bind("<Button-1>", lambda _e: self._toggle())

        self.status = tk.Label(r, text="Tap to Connect", bg=BG, fg=INK, font=("Segoe UI Semibold", 16))
        self.status.pack(pady=(4, 0))
        self.timer = tk.Label(r, text="", bg=BG, fg=MUTED, font=("Consolas", 11))
        self.timer.pack(pady=(2, 10))

        # selected "server" row (one server for now; a picker comes when there are more)
        row = tk.Frame(r, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        row.pack(fill="x", padx=24, pady=(6, 4), ipady=10)
        tk.Label(row, text="\U0001F30D", bg=CARD, fg=BRAND2, font=("Segoe UI Emoji", 13)).pack(side="left", padx=(14, 8))
        tk.Label(row, text="ShieldsVPN server", bg=CARD, fg=INK, font=("Segoe UI", 11)).pack(side="left")
        tk.Label(row, text="✔", bg=CARD, fg=BRAND, font=("Segoe UI", 12)).pack(side="right", padx=14)

        # details card (filled when connected)
        self.card = tk.Frame(r, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        self.card.pack(fill="x", padx=24, pady=(6, 0))
        self.detail_rows = {}
        for key, label in (("ip", "Your VPN address"), ("enc", "Encryption"), ("srv", "Server")):
            line = tk.Frame(self.card, bg=CARD)
            line.pack(fill="x", padx=14, pady=5)
            tk.Label(line, text=label, bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
            val = tk.Label(line, text="–", bg=CARD, fg=INK, font=("Segoe UI Semibold", 10))
            val.pack(side="right")
            self.detail_rows[key] = val

        tk.Label(r, text="Post-quantum VPN · ML-KEM + ML-DSA", bg=BG, fg="#475569",
                 font=("Segoe UI", 8)).pack(side="bottom", pady=12)
        self._draw(GREY)

    def _draw(self, accent: str) -> None:
        c, d = self.cv, self.DIAM
        c.delete("all")
        pad = 30
        cx = cy = pad + d / 2
        c.create_oval(pad - 8, pad - 8, pad + d + 8, pad + d + 8, outline=LINE, width=2)        # soft outer
        c.create_oval(pad, pad, pad + d, pad + d, outline=accent, width=7)                       # state ring
        c.create_oval(pad + 16, pad + 16, pad + d - 16, pad + d - 16, fill=CARD, outline="")     # inner fill
        # power glyph (arc with a gap at the top + a vertical bar through it)
        r = d * 0.26
        c.create_arc(cx - r, cy - r, cx + r, cy + r, start=118, extent=304, style="arc",
                     outline=accent, width=9)
        c.create_line(cx, cy - r - 8, cx, cy - 4, fill=accent, width=9, capstyle="round")

    # ---------------------------------------------------------------- state
    def _toggle(self) -> None:
        if self.state in ("connected", "connecting", "reconnecting"):
            self.ctl.disconnect()
            self._apply("disconnected", {})
            return
        # need admin on Windows to create the adapter -> hand off to an elevated copy
        if sys.platform == "win32" and not _is_admin():
            if _relaunch_elevated(self.config_path):
                self._close()
            else:
                self._apply("error", {"message": "Administrator access was declined."})
            return
        self.ctl.connect()

    def _pump(self) -> None:
        try:
            while True:
                state, info = self.events.get_nowait()
                self._apply(state, info)
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _apply(self, state: str, info: dict) -> None:
        if state == "disconnected" and self.state == "error":
            return  # keep the error visible until the next action
        self.state = state
        if state == "connected":
            self.info = info or self.info
            self.connected_at = self.connected_at or time.time()
        else:
            if state in ("disconnected", "error"):
                self.connected_at = None
            self.info = info if state == "error" else {}
        accent, headline, subtext = STATES.get(state, STATES["disconnected"])
        self._draw(accent)
        self.status.config(text=headline, fg=INK if state != "error" else RED)
        self.sub.config(text=(self.info.get("message") if state == "error" else subtext))
        if state == "connected":
            self.detail_rows["ip"].config(text=", ".join(a.split("/")[0] for a in
                                                          (self.info.get("address") or "").split(", ")) or "–")
            self.detail_rows["enc"].config(text=describe_suite(self.info.get("suite", "")) or "–")
            self.detail_rows["srv"].config(text=self.info.get("server") or self.server_name)
        else:
            for v in self.detail_rows.values():
                v.config(text="–")

    def _tick(self) -> None:
        if self.state == "connected" and self.connected_at:
            s = int(time.time() - self.connected_at)
            self.timer.config(text=f"Connected  {s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}")
        else:
            self.timer.config(text="")
        self.root.after(500, self._tick)

    def _close(self) -> None:
        try:
            self.ctl.disconnect(wait=6)
        finally:
            self.root.destroy()


def install_shortcut(config_path: str) -> list[str]:
    """Create a 'ShieldsVPN' Desktop + Start-menu shortcut that opens this app (double-click to run)."""
    import subprocess

    from . import logo, winui
    icon = logo.ensure_icons(os.path.join(winui.app_dir(), "icons"))["brand"]
    target = winui.windowless_python()
    args = f'-m pqvpn app -c "{os.path.abspath(config_path)}"'
    created = []
    for folder in ("Desktop", "Programs"):
        ps = (f"$s=(New-Object -ComObject WScript.Shell);"
              f"$d=[Environment]::GetFolderPath('{folder}');"
              f"$l=$s.CreateShortcut((Join-Path $d 'ShieldsVPN.lnk'));"
              f"$l.TargetPath='{target}';$l.Arguments='{args.replace(chr(39), chr(39) * 2)}';"
              f"$l.WorkingDirectory='{winui.project_root()}';$l.IconLocation='{icon},0';"
              f"$l.Description='ShieldsVPN — post-quantum VPN';$l.Save();(Join-Path $d 'ShieldsVPN.lnk')")
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             capture_output=True, text=True)
        if out.returncode == 0:
            path = out.stdout.strip()
            try:
                winui.set_shortcut_app_id(path, winui.APP_ID)
            except OSError:
                pass
            created.append(path)
    return created


def main(config_path: str, autoconnect: bool = False) -> int:
    root = tk.Tk()
    try:
        if sys.platform == "win32":
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass
    ShieldsApp(root, config_path, autoconnect=autoconnect)
    root.mainloop()
    return 0
