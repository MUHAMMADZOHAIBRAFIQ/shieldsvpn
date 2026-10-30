"""ShieldsVPN desktop app: a simple one-tap "Tap to Connect" window.

A friendly front end for end users, built on the same client engine as the tray
app (``runner.run_client``): a big power button that connects/disconnects, a live
status, and the connection details.  Pure standard library (tkinter + ctypes).

Run it with::

    python -m pqvpn app -c client.toml

On Windows the VPN needs Administrator (to create the network adapter); the app
asks for it through UAC the moment you press Connect.

A PC registered with the portal (``python -m pqvpn app --portal https://...``, see
desktop_account.py) also gets the plan row: Free time earned by viewing an ad page,
sign-in, and Pro.  Free time is enforced by the VPN server; the app also stops the
tunnel itself when the time is up, with a clear message.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser

from . import desktop_account
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


def open_url(url: str) -> None:
    # Web addresses only: these links come from the portal, and explorer.exe would also open files or start programs.
    if not re.fullmatch(r"https?://[^\s\"]+", url or ""):
        return
    if sys.platform == "win32":
        subprocess.Popen(["explorer.exe", url])  # the user's normal (non-elevated) default browser
    else:
        webbrowser.open(url)


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
            cfg = desktop_account.load_config(self.config_path)  # re-read each time: picks up a new profile
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
        self.account = desktop_account.account_for_config(self.config_path)
        self.me: dict | None = None
        self.me_at = 0.0          # when `me` was fetched (local clock)
        self.note, self.note_until = "", 0.0   # a status message shown in the plan row for a while
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(80, self._pump)
        self.root.after(250, self._tick)
        if self.account is not None:
            self.root.after(100, self.refresh_me)
        if autoconnect:
            self.root.after(300, self._toggle)

    # ---------------------------------------------------------------- layout
    def _build(self) -> None:
        r = self.root
        r.title("ShieldsVPN")
        r.configure(bg=BG)
        r.geometry("400x810" if self.account is not None else "400x660")
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

        if self.account is not None:   # Free / Pro (a PC registered with the portal)
            plan = tk.Frame(r, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            plan.pack(fill="x", padx=24, pady=(6, 4))
            self.plan_label = tk.Label(plan, text="Checking your plan…", bg=CARD, fg=INK,
                                       font=("Segoe UI Semibold", 11), anchor="w")
            self.plan_label.pack(fill="x", padx=14, pady=(10, 2))
            self.plan_sub = tk.Label(plan, text="", bg=CARD, fg=MUTED, font=("Segoe UI", 9), anchor="w",
                                     wraplength=330, justify="left")
            self.plan_sub.pack(fill="x", padx=14)
            buttons = tk.Frame(plan, bg=CARD)
            buttons.pack(fill="x", padx=10, pady=(6, 10))
            style = dict(bg=LINE, fg=INK, activebackground=GREY, activeforeground=INK, relief="flat",
                         font=("Segoe UI", 9), padx=10, pady=4, cursor="hand2")
            self.btn_ad = tk.Button(buttons, text="Get free time", command=self.watch_ad, **style)
            self.btn_pro = tk.Button(buttons, text="Go Pro", command=self.go_pro,
                                     **{**style, "bg": AMBER, "fg": "#1c1917"})
            self.btn_sign = tk.Button(buttons, text="Sign in", command=self.sign_in_or_out, **style)
            for b in (self.btn_ad, self.btn_pro, self.btn_sign):
                b.pack(side="left", padx=4)

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
        if self._no_free_time():
            self._apply("error", {"message": "No free time left. Click “Get free time” first, or go Pro."})
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
                if state in ("_ok", "_fail"):   # a background portal call finished: run its callback here
                    then, value = info
                    if then is not None:
                        then(value if state == "_ok" else None, value if state == "_fail" else None)
                else:
                    self._apply(state, info)
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    # ---------------------------------------------------------------- Free / Pro (registered PCs)
    def bg(self, fn, then=None) -> None:
        """Run a portal call off the UI thread; then(result, error) runs back on the UI thread."""
        def run():
            try:
                self.events.put(("_ok", (then, fn())))
            except Exception as exc:  # noqa: BLE001 -- shown to the user
                self.events.put(("_fail", (then, exc)))
        threading.Thread(target=run, name="shieldsvpn-portal", daemon=True).start()

    def _free_left(self) -> float:
        me = self.me or {}
        server_now = me.get("now", time.time()) + (time.time() - self.me_at)
        return me.get("free_until", 0) - server_now

    def _is_pro(self) -> bool:
        return bool(self.me) and self.me.get("plan") == "premium"

    def _no_free_time(self) -> bool:
        return self.account is not None and self.me is not None and not self._is_pro() and self._free_left() <= 0

    def refresh_me(self, then=None) -> None:
        def done(me, err):
            if me is not None:
                self.me, self.me_at = me, time.time()
                if me.get("device", {}).get("renew") and self.state in ("disconnected", "error"):
                    self.bg(self.account.renew)
            elif err is not None and self.me is None:
                self._say(f"Cannot reach the ShieldsVPN server: {getattr(err, 'message', None) or err}")
            self._show_plan()
            if then is not None:
                then(me)
        self.bg(self.account.me, done)

    def _poll_me(self, until: float, before: float, field: str = "free_until") -> None:
        """After an ad page or a checkout: re-check until the plan changes (or give up at `until`)."""
        def done(me):
            changed = me is not None and (me.get(field) or 0) > before
            if not changed and time.time() < until:
                self.root.after(5000, lambda: self._poll_me(until, before, field))
        self.refresh_me(done)

    def _show_plan(self) -> None:
        if self.account is None or self.me is None:
            return
        me, feats = self.me, self.me.get("features", {})
        signed_in = me.get("account") is not None
        if self._is_pro():
            until = me.get("pro_until")
            self.plan_label.config(text="ShieldsVPN Pro — unlimited", fg=GREEN)
            self.plan_sub.config(text="No ads and unlimited time." +
                                 (f" Paid until {time.strftime('%d %b %Y', time.localtime(until))}." if until else ""))
        else:
            left = max(0, int(self._free_left()))
            self.plan_label.config(text=f"Free plan — {left // 3600:02d}:{left % 3600 // 60:02d}:{left % 60:02d} left",
                                   fg=INK if left else AMBER)
            self.plan_sub.config(text=f"View a short ad page to get {me.get('free_minutes', 30)} minutes "
                                      f"({me.get('rewards_left_today', 0)} left today).")
        if time.time() < self.note_until:
            self.plan_sub.config(text=self.note)
        self.btn_ad.config(state="normal" if feats.get("web_ads") and not self._is_pro() else "disabled")
        prices = me.get("prices") or []
        self.btn_pro.config(text="Manage subscription" if self._is_pro() else
                            "Go Pro" + (f" · {prices[0]['label']}" if len(prices) == 1 else ""),
                            state="normal" if feats.get("payments") and feats.get("accounts") else "disabled")
        self.btn_sign.config(text="Sign out" if signed_in else "Sign in",
                             state="normal" if feats.get("accounts") else "disabled")

    def _say(self, text: str, seconds: float = 30) -> None:
        self.note, self.note_until = text, time.time() + seconds
        if hasattr(self, "plan_sub"):
            self.plan_sub.config(text=text)

    def _fail(self, title: str, err) -> None:
        self._say(f"{title}: {getattr(err, 'message', None) or err}")

    def watch_ad(self) -> None:
        before = (self.me or {}).get("free_until", 0)

        def done(url, err):
            if err is not None:
                return self._fail("Free time", err)
            open_url(url)
            self._say("Keep the ad page open until its button unlocks, press it, then come back.", 120)
            self.root.after(5000, lambda: self._poll_me(time.time() + 180, before))
        self.bg(self.account.web_reward_url, done)

    def go_pro(self) -> None:
        if self._is_pro():
            return self.bg(lambda: self.account.link("/api/v1/manage"),
                           lambda url, err: open_url(url) if url else self._fail("Subscription", err))
        if not (self.me or {}).get("account"):
            return AccountDialog(self, "signIn", "Pro is tied to an account. The Free plan needs none.")
        prices = (self.me or {}).get("prices") or []
        if len(prices) > 1:
            return PlanDialog(self, prices, self._checkout)
        self._checkout(prices[0]["period"] if prices else "")

    def _checkout(self, period: str) -> None:
        """Open Paddle's checkout for the chosen plan ("" = the portal's default plan)."""
        before = (self.me or {}).get("pro_until") or 0

        def done(url, err):
            if err is not None:
                return self._fail("Go Pro", err)
            open_url(url)
            self._say("Finish the payment in your browser; Pro switches on here within a minute.", 300)
            self.root.after(10000, lambda: self._poll_me(time.time() + 900, before, "pro_until"))
        body = {"period": period} if period else {}
        self.bg(lambda: self.account.link("/api/v1/checkout", body), done)

    def sign_in_or_out(self) -> None:
        if (self.me or {}).get("account"):
            self.bg(lambda: self.account.call("POST", "/api/v1/logout", {}),
                    lambda me, err: self.refresh_me() if err is None else self._fail("Sign out", err))
        else:
            AccountDialog(self, "signIn", "")

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
        if self.account is not None and self.me is not None:
            self._show_plan()
            if self.state in ("connected", "connecting", "reconnecting") and self._no_free_time():
                # The server ends a Free session when its time is up; stop cleanly and say why.
                self.ctl.disconnect()
                self._apply("error", {"message": "Your free time is over. Get more free time, or go Pro."})
        self.root.after(500, self._tick)

    def _close(self) -> None:
        try:
            self.ctl.disconnect(wait=6)
        finally:
            self.root.destroy()


class PlanDialog:
    """Choose the Pro plan (weekly / monthly / yearly, as priced by the administrator) before the checkout opens."""

    def __init__(self, app: ShieldsApp, prices: list[dict], choose):
        self.top = tk.Toplevel(app.root, bg=BG)
        self.top.title("ShieldsVPN Pro")
        self.top.resizable(False, False)
        self.top.transient(app.root)
        f = tk.Frame(self.top, bg=BG, padx=22, pady=16)
        f.pack(fill="both")
        tk.Label(f, text="Choose your plan", bg=BG, fg=INK, font=("Segoe UI Semibold", 14)).pack(anchor="w")
        tk.Label(f, text="You pay on Paddle's secure page in your browser. Cancel any time.", bg=BG, fg=MUTED,
                 wraplength=300, justify="left").pack(anchor="w", pady=(4, 8))
        for p in prices:
            tk.Button(f, text=f"{p.get('name', '')}  ·  {p.get('label', '')}",
                      command=lambda period=p.get("period", ""): self._pick(choose, period), bg=BRAND, fg="white",
                      relief="flat", activebackground=BRAND2, font=("Segoe UI Semibold", 10), pady=6,
                      cursor="hand2").pack(fill="x", pady=4)
        tk.Button(f, text="Cancel", command=self.top.destroy, bg=BG, fg="#a5b4fc", relief="flat", activebackground=BG,
                  cursor="hand2", font=("Segoe UI", 9)).pack(pady=(6, 0))
        self.top.grab_set()

    def _pick(self, choose, period: str) -> None:
        self.top.destroy()
        choose(period)


class AccountDialog:
    """Sign in / create an account / verify the email / reset the password (the same steps as the Android app)."""

    TITLES = {"signIn": "Sign in", "signUp": "Create your account", "verify": "Check your email",
              "forgot": "Forgot your password?", "reset": "Choose a new password"}

    def __init__(self, app: ShieldsApp, mode: str, note: str):
        self.app = app
        self.top = tk.Toplevel(app.root, bg=BG)
        self.top.title("ShieldsVPN account")
        self.top.resizable(False, False)
        self.top.transient(app.root)
        self.email, self.password, self.code = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.need_code = False
        self.frame = None
        self.show(mode, note)
        self.top.grab_set()

    def show(self, mode: str, note: str = "", error: str = "") -> None:
        self.mode = mode
        if self.frame is not None:
            self.frame.destroy()
        f = self.frame = tk.Frame(self.top, bg=BG, padx=22, pady=16)
        f.pack(fill="both")
        tk.Label(f, text=self.TITLES[mode], bg=BG, fg=INK, font=("Segoe UI Semibold", 14)).pack(anchor="w")
        if note:
            tk.Label(f, text=note, bg=BG, fg=MUTED, wraplength=300, justify="left").pack(anchor="w", pady=(4, 0))

        def field(label, var, secret=False):
            tk.Label(f, text=label, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 2))
            entry = tk.Entry(f, textvariable=var, show="•" if secret else "", width=34, bg=CARD, fg=INK,
                             insertbackground=INK, relief="flat", font=("Segoe UI", 11))
            entry.pack(fill="x", ipady=5)
            return entry

        first = None
        if mode in ("signIn", "signUp", "forgot"):
            first = field("Email", self.email)
        if mode in ("signIn", "signUp", "reset"):
            field("Password" if mode == "signIn" else "New password (at least 10 characters)", self.password, True)
        if mode in ("verify", "reset") or (mode == "signIn" and self.need_code):
            code = field("Authenticator code" if mode == "signIn" else "Code from the email", self.code)
            first = first if mode == "signIn" else code
        if error:
            tk.Label(f, text=error, bg=BG, fg=RED, wraplength=300, justify="left").pack(anchor="w", pady=(10, 0))
        action = {"signIn": "Sign in", "signUp": "Create account", "verify": "Verify", "forgot": "Email me a code",
                  "reset": "Change password"}[mode]
        self.submit_btn = tk.Button(f, text=action, command=self.submit, bg=BRAND, fg="white", relief="flat",
                                    activebackground=BRAND2, font=("Segoe UI Semibold", 10), pady=6)
        self.submit_btn.pack(fill="x", pady=(14, 6))
        links = tk.Frame(f, bg=BG)
        links.pack()
        for label, target in ((("Create an account", "signUp"), ("Forgot password?", "forgot")) if mode == "signIn"
                              else (("Back to sign in", "signIn"),)):
            tk.Button(links, text=label, command=lambda t=target: self.show(t), bg=BG, fg="#a5b4fc", relief="flat",
                      activebackground=BG, cursor="hand2", font=("Segoe UI", 9)).pack(side="left", padx=4)
        self.top.bind("<Return>", lambda _e: self.submit())
        if first is not None:
            first.focus_set()

    def submit(self) -> None:
        mode, email, pw, code = self.mode, self.email.get().strip(), self.password.get(), self.code.get().strip()
        if mode == "signUp" and len(pw) < 10:
            return self.show(mode, error="Use at least 10 characters.")
        calls = {
            "signIn": ("/api/v1/login", {"login": email, "password": pw, "code": code}),
            "signUp": ("/api/v1/signup", {"email": email, "password": pw}),
            "verify": ("/api/v1/signup/verify", {"email": email, "code": code}),
            "forgot": ("/api/v1/forgot", {"login": email}),
            "reset": ("/api/v1/forgot/verify", {"login": email, "code": code, "password": pw}),
        }
        path, body = calls[mode]
        self.submit_btn.config(state="disabled", text="Please wait…")
        self.app.bg(lambda: self.app.account.call("POST", path, body), self.done)

    def done(self, _result, err) -> None:
        if not self.top.winfo_exists():
            return
        mode = self.mode
        if err is None:
            if mode in ("signIn", "verify"):
                self.top.destroy()
                self.app.refresh_me()
            elif mode == "signUp":
                self.code.set("")
                self.show("verify", f"We sent a 6-digit code to {self.email.get().strip()}. It expires in 10 minutes.")
            elif mode == "forgot":
                self.code.set("")
                self.password.set("")
                self.show("reset", "If an account matches, a 6-digit code is on its way to its email address.")
            elif mode == "reset":
                self.password.set("")
                self.show("signIn", "Your password was changed. Sign in with the new one.")
            return
        code = getattr(err, "code", "")
        if mode == "signIn" and code == "totp_required":
            self.need_code = True
            return self.show("signIn", "Enter the 6-digit code from your authenticator app.")
        if mode == "signIn" and code == "unverified":
            return self.show("verify", "Verify your email first: enter the code we sent you.")
        self.show(mode, error=getattr(err, "message", None) or str(err))


def install_shortcut(config_path: str) -> list[str]:
    """Create a 'ShieldsVPN' Desktop + Start-menu shortcut that opens this app (double-click to run)."""
    import subprocess

    from . import logo, winui
    icon = logo.ensure_icons(os.path.join(winui.app_dir(), "icons"))["brand"]
    target = winui.windowless_python()
    args = f'-m pqvpn app -c "{os.path.abspath(config_path)}"'
    created = []
    for folder in ("Desktop", "Programs"):
        ps = winui.shortcut_script(folder, target, args, icon, "ShieldsVPN — post-quantum VPN")
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
