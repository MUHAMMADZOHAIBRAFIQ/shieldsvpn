"""Windows notification-area (system tray) app for the pqvpn client.

  * Shield icon whose colour follows the connection: grey = disconnected,
    amber = connecting / reconnecting, green = connected, red = error.
  * Windows notifications on connect, disconnect and errors.
  * Right-click menu: status, Connect, Disconnect, Open portal, Open log, Exit;
    double-click toggles the connection (or opens the portal when connected).
  * Elevates itself through UAC (TUN adapters and routes need Administrator),
    allows a single instance, survives Explorer restarts (TaskbarCreated) and
    disconnects cleanly on logoff/shutdown.

Pure Win32 through ctypes (Shell_NotifyIconW, a message-only window and a
popup menu); the VPN client runs on an asyncio loop in a background thread.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import logging.handlers
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes as wt

from . import logo
from .config import load_client
from .crypto.suites import describe_suite
from .runner import run_client

log = logging.getLogger("pqvpn.tray")

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
WM_APP, WM_DESTROY, WM_CLOSE, WM_COMMAND, WM_NULL = 0x8000, 0x0002, 0x0010, 0x0111, 0x0000
WM_QUERYENDSESSION, WM_ENDSESSION = 0x0011, 0x0016
WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_CONTEXTMENU, NIN_BALLOONUSERCLICK = 0x0203, 0x0205, 0x007B, 0x0405
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO, NIF_GUID, NIF_SHOWTIP = 0x01, 0x02, 0x04, 0x10, 0x20, 0x80
WM_TIMER = 0x0113
NIIF_USER, NIIF_LARGE_ICON, NIIF_RESPECT_QUIET_TIME = 0x04, 0x20, 0x80
IMAGE_ICON, LR_LOADFROMFILE = 1, 0x10
MF_STRING, MF_GRAYED, MF_SEPARATOR, MF_DEFAULT = 0x0, 0x1, 0x800, 0x1000
TPM_RIGHTBUTTON, TPM_RETURNCMD, TPM_NONOTIFY = 0x0002, 0x0100, 0x0080
ERROR_ALREADY_EXISTS = 183


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT), ("uFlags", wt.UINT),
                ("uCallbackMessage", wt.UINT), ("hIcon", wt.HICON), ("szTip", wt.WCHAR * 128),
                ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD), ("szInfo", wt.WCHAR * 256),
                ("uVersion", wt.UINT), ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", wt.HICON)]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
                ("lpszClassName", wt.LPCWSTR), ("hIconSm", wt.HICON)]


user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

for _fn, _res, _args in (
    (user32.RegisterClassExW, wt.ATOM, [ctypes.POINTER(WNDCLASSEXW)]),
    (user32.CreateWindowExW, wt.HWND, [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]),
    (user32.DefWindowProcW, LRESULT, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]),
    (user32.GetMessageW, wt.BOOL, [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]),
    (user32.TranslateMessage, wt.BOOL, [ctypes.POINTER(wt.MSG)]),
    (user32.DispatchMessageW, LRESULT, [ctypes.POINTER(wt.MSG)]),
    (user32.PostMessageW, wt.BOOL, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]),
    (user32.PostQuitMessage, None, [ctypes.c_int]),
    (user32.DestroyWindow, wt.BOOL, [wt.HWND]),
    (user32.LoadImageW, wt.HANDLE, [wt.HINSTANCE, wt.LPCWSTR, wt.UINT, ctypes.c_int, ctypes.c_int, wt.UINT]),
    (user32.DestroyIcon, wt.BOOL, [wt.HICON]),
    (user32.GetSystemMetrics, ctypes.c_int, [ctypes.c_int]),
    (user32.CreatePopupMenu, wt.HMENU, []),
    (user32.AppendMenuW, wt.BOOL, [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]),
    (user32.TrackPopupMenu, wt.BOOL, [wt.HMENU, wt.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.HWND,
                                      wt.LPVOID]),
    (user32.DestroyMenu, wt.BOOL, [wt.HMENU]),
    (user32.GetCursorPos, wt.BOOL, [ctypes.POINTER(wt.POINT)]),
    (user32.SetForegroundWindow, wt.BOOL, [wt.HWND]),
    (user32.RegisterWindowMessageW, wt.UINT, [wt.LPCWSTR]),
    (user32.MessageBoxW, ctypes.c_int, [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT]),
    (user32.SetTimer, ctypes.c_size_t, [wt.HWND, ctypes.c_size_t, wt.UINT, wt.LPVOID]),
    (user32.FindWindowW, wt.HWND, [wt.LPCWSTR, wt.LPCWSTR]),
    (user32.GetWindowThreadProcessId, wt.DWORD, [wt.HWND, ctypes.POINTER(wt.DWORD)]),
    (kernel32.CloseHandle, wt.BOOL, [wt.HANDLE]),
    (shell32.Shell_NotifyIconW, wt.BOOL, [wt.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]),
    (shell32.ShellExecuteW, wt.HINSTANCE, [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, ctypes.c_int]),
    (kernel32.GetModuleHandleW, wt.HMODULE, [wt.LPCWSTR]),
    (kernel32.CreateMutexW, wt.HANDLE, [wt.LPVOID, wt.BOOL, wt.LPCWSTR]),
):
    _fn.restype, _fn.argtypes = _res, _args

STATE_TEXT = {
    "disconnected": "Disconnected",
    "connecting": "Connecting…",
    "reconnecting": "Reconnecting…",
    "connected": "Connected",
    "error": "Connection error",
}
STATE_ICON = {"disconnected": "disconnected", "connecting": "connecting", "reconnecting": "connecting",
              "connected": "connected", "error": "error"}
ID_CONNECT, ID_DISCONNECT, ID_PORTAL, ID_LOG, ID_EXIT = 1001, 1002, 1003, 1004, 1005
# Windows attributes notifications to this ID; the Start-menu shortcut carries the
# same ID, so the notification header reads "ShieldsVPN" with the shield icon.
APP_ID = "PQVPN.PostQuantumVPN"
ICON_GUID = "6f1d8c52-3b7e-4a5c-9e2f-51a7c0d4b9e3"  # stable identity of the ShieldsVPN tray icon
SHOW_MESSAGE = "PQVPN_ShowTrayIcon"  # sent by a second launch: "re-show yourself"


def friendly_suite(name: str) -> str:
    return describe_suite(name)


def short_address(addr: str) -> str:
    return ", ".join(a.split("/")[0] for a in addr.split(", ")) if addr else ""


def app_dir() -> str:
    d = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "pqvpn")
    os.makedirs(d, exist_ok=True)
    return d


def is_admin() -> bool:
    return bool(shell32.IsUserAnAdmin())


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def windowless_python() -> str:
    exe = sys.executable
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return cand if os.path.exists(cand) else exe


def relaunch_elevated(config_path: str, extra: str = "") -> bool:
    """Ask UAC to start the tray app as Administrator (no console window)."""
    args = f'-m pqvpn tray -c "{os.path.abspath(config_path)}" {extra}'.strip()
    rc = shell32.ShellExecuteW(None, "runas", windowless_python(), args, project_root(), 1)
    return (rc or 0) > 32


def open_url(url: str) -> None:
    # explorer.exe hands the URL to the user's (non-elevated) default browser
    subprocess.Popen(["explorer.exe", url])


class TrayApp:
    WM_TRAY = WM_APP + 1
    WM_STATE = WM_APP + 2
    HEALTH_TIMER = 1

    def __init__(self, config_path: str, autoconnect: bool = True, icon_guid: str = ICON_GUID):
        self.config_path = os.path.abspath(config_path)
        self.cfg = load_client(self.config_path)
        self.autoconnect = autoconnect
        # A GUID identity (NIF_GUID) is Microsoft's recommended way to identify a
        # notification icon: unlike (exe, uID) it cannot collide with other apps
        # that happen to run under the same pythonw.exe.
        import uuid
        self._guid = GUID.from_buffer_copy(uuid.UUID(icon_guid).bytes_le)
        self._use_guid = True
        self.state, self.info = "disconnected", {}
        self.shown_state = None
        self._lock = threading.Lock()
        self.icons_dir = os.path.join(app_dir(), "icons")
        self.icon_files = logo.ensure_icons(self.icons_dir)
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, name="vpn-loop", daemon=True)
        self.future = None
        self.hwnd = None
        self._wndproc = WNDPROC(self._wndproc_impl)  # keep a reference: called from C
        self._hicons: dict[tuple[str, int], int] = {}

    # -------------------------------------------------------------- icons
    def _icon(self, state: str, large: bool = False) -> int:
        size = user32.GetSystemMetrics(11 if large else 49)  # SM_CXICON / SM_CXSMICON (DPI-aware)
        key = (state, size)
        if key not in self._hicons:
            self._hicons[key] = user32.LoadImageW(None, self.icon_files[state], IMAGE_ICON, size, size,
                                                  LR_LOADFROMFILE)
        return self._hicons[key]

    def _nid(self, flags: int = 0) -> NOTIFYICONDATAW:
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = flags
        if self._use_guid:
            nid.uFlags |= NIF_GUID
            nid.guidItem = self._guid
        return nid

    def _add_icon(self) -> bool:
        if self._update_icon(add=True):
            return True
        if self._use_guid:
            # A stale registration of our GUID (e.g. after a crash) blocks NIM_ADD: clear it once.
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid()))
            if self._update_icon(add=True):
                return True
            log.warning("GUID-based tray icon failed (error %d); falling back to uID identity",
                        ctypes.get_last_error())
            self._use_guid = False
        return self._update_icon(add=True)

    def _tooltip(self) -> str:
        with self._lock:
            state, info = self.state, dict(self.info)
        text = f"ShieldsVPN — {STATE_TEXT.get(state, state)}"
        if state == "connected":
            text += (f"\n{info.get('server', '')} · {short_address(info.get('address', ''))}"
                     f"\n{friendly_suite(info.get('suite', ''))}")
        elif state == "error":
            text += f"\n{info.get('message', '')}"
        return text[:127]

    def _update_icon(self, add: bool = False) -> bool:
        with self._lock:
            state = self.state
        nid = self._nid(NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP)
        nid.uCallbackMessage = self.WM_TRAY
        nid.hIcon = self._icon(STATE_ICON.get(state, "disconnected"))
        nid.szTip = self._tooltip()
        return bool(shell32.Shell_NotifyIconW(NIM_ADD if add else NIM_MODIFY, ctypes.byref(nid)))

    def notify(self, title: str, text: str, state: str) -> None:
        nid = self._nid(NIF_INFO)
        nid.szInfoTitle = title[:63]
        nid.szInfo = text[:255]
        nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON | NIIF_RESPECT_QUIET_TIME
        nid.hBalloonIcon = self._icon(STATE_ICON.get(state, "brand"), large=True)
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    # -------------------------------------------------------------- VPN control (UI thread)
    def connect(self) -> None:
        if self.future is not None and not self.future.done():
            return
        try:
            self.cfg = load_client(self.config_path)  # pick up a newly downloaded profile
        except Exception as exc:
            self._on_state("error", {"message": f"profile: {exc}"})
            return
        self.future = asyncio.run_coroutine_threadsafe(self._client(), self.loop)

    async def _client(self) -> None:
        try:
            await run_client(self.cfg, on_state=self._on_state)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # incl. SystemExit from privilege checks
            log.exception("client stopped")
            self._on_state("error", {"message": str(exc) or type(exc).__name__})

    def disconnect(self, wait: float = 0) -> None:
        fut = self.future
        if fut is not None and not fut.done():
            fut.cancel()
            if wait:
                try:
                    fut.result(timeout=wait)
                except BaseException:
                    pass

    def _on_state(self, state: str, info: dict) -> None:
        """Called on the VPN thread; marshal to the UI thread."""
        log.info("state: %s %s", state, info)
        with self._lock:
            if state == "disconnected" and self.state == "error":
                info = self.info  # keep the error visible
                state = "error"
            self.state, self.info = state, dict(info)
        if self.hwnd:
            user32.PostMessageW(self.hwnd, self.WM_STATE, 0, 0)

    def _apply_state(self) -> None:
        with self._lock:
            state, info = self.state, dict(self.info)
        self._update_icon()
        if state == self.shown_state:
            return
        previous, self.shown_state = self.shown_state, state
        if state == "connected":
            self.notify("ShieldsVPN connected",
                        f"Post-quantum protection is on.\n{info.get('server', '')} — your address "
                        f"{short_address(info.get('address', ''))}\n{friendly_suite(info.get('suite', ''))}",
                        "connected")
        elif state == "reconnecting":
            self.notify("ShieldsVPN reconnecting", "The connection was interrupted; re-establishing it…",
                        "connecting")
        elif state == "error":
            self.notify("ShieldsVPN error", info.get("message", "Connection failed")[:200], "error")
        elif state == "disconnected" and previous in ("connected", "reconnecting"):
            self.notify("ShieldsVPN disconnected", "Your traffic is no longer protected by the VPN.", "disconnected")

    # -------------------------------------------------------------- menu
    def _show_menu(self) -> None:
        with self._lock:
            state, info = self.state, dict(self.info)
        menu = user32.CreatePopupMenu()
        busy = self.future is not None and not self.future.done()
        portal = info.get("portal") or self.cfg.portal_url
        status = f"●  {STATE_TEXT.get(state, state)}"
        if state == "connected":
            status += f" — {info.get('server', '')}"
        user32.AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, status)
        if state == "connected":
            user32.AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, f"     {short_address(info.get('address', ''))}  ·  "
                                                               f"{friendly_suite(info.get('suite', ''))}")
            user32.AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, f"     identity {info.get('key_alg', '')}")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(menu, MF_STRING | (MF_GRAYED if busy else MF_DEFAULT), ID_CONNECT, "Connect")
        user32.AppendMenuW(menu, MF_STRING | (0 if busy else MF_GRAYED), ID_DISCONNECT, "Disconnect")
        user32.AppendMenuW(menu, MF_STRING | (0 if portal else MF_GRAYED), ID_PORTAL, "Open portal")
        user32.AppendMenuW(menu, MF_STRING, ID_LOG, "Open log")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(menu, MF_STRING, ID_EXIT, "Exit")
        pt = wt.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)  # required so the menu closes when clicking elsewhere
        cmd = user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0,
                                    self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(menu)
        self._command(cmd, portal)

    def _command(self, cmd: int, portal: str = "") -> None:
        if cmd == ID_CONNECT:
            self.connect()
        elif cmd == ID_DISCONNECT:
            self.disconnect()
        elif cmd == ID_PORTAL and portal:
            open_url(portal)
        elif cmd == ID_LOG:
            subprocess.Popen(["notepad.exe", os.path.join(app_dir(), "pqvpn-tray.log")])
        elif cmd == ID_EXIT:
            user32.DestroyWindow(self.hwnd)

    # -------------------------------------------------------------- window
    def _wndproc_impl(self, hwnd, msg, wparam, lparam):
        try:
            if msg == self.WM_TRAY:
                event = lparam & 0xFFFF
                if event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._show_menu()
                elif event == WM_LBUTTONDBLCLK:
                    with self._lock:
                        state, portal = self.state, self.info.get("portal") or self.cfg.portal_url
                    if state == "connected" and portal:
                        open_url(portal)
                    elif self.future is None or self.future.done():
                        self.connect()
                elif event == NIN_BALLOONUSERCLICK:
                    with self._lock:
                        portal = self.info.get("portal") or self.cfg.portal_url
                    if portal:
                        open_url(portal)
                return 0
            if msg == self.WM_STATE:
                self._apply_state()
                return 0
            if msg == self._taskbar_created:  # Explorer restarted: the icon must be re-added
                self._add_icon()
                return 0
            if msg == WM_TIMER and wparam == self.HEALTH_TIMER:
                # Self-healing: if anything removed our icon, put it back.
                if not self._update_icon():
                    log.warning("tray icon was missing; re-adding it")
                    self._add_icon()
                return 0
            if msg == self._show_message:  # another launch asked us to become visible
                self._add_icon() if not self._update_icon() else None
                with self._lock:
                    state = self.state
                self.notify("ShieldsVPN is running", f"{STATE_TEXT.get(state, state)}. Right-click the shield "
                            "icon for options.", STATE_ICON.get(state, "brand"))
                return 0
            if msg == WM_QUERYENDSESSION:
                return 1
            if msg == WM_ENDSESSION and wparam:
                self.disconnect(wait=5)
                return 0
            if msg == WM_DESTROY:
                self.disconnect(wait=8)
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid()))
                user32.PostQuitMessage(0)
                return 0
        except Exception:
            log.exception("tray window procedure")
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def run(self) -> int:
        try:
            user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # per-monitor v2: crisp icons
        except (AttributeError, OSError):
            pass
        self._thread.start()
        hinst = kernel32.GetModuleHandleW(None)
        self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        self._show_message = user32.RegisterWindowMessageW(SHOW_MESSAGE)
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = "pqvpnTrayWindow"
        wc.hIcon = self._icon("brand", large=True)
        wc.hIconSm = self._icon("brand")
        if not user32.RegisterClassExW(ctypes.byref(wc)):
            raise OSError(ctypes.get_last_error(), "RegisterClassExW failed")
        # A hidden top-level window (not message-only) so it receives TaskbarCreated broadcasts.
        self.hwnd = user32.CreateWindowExW(0, "pqvpnTrayWindow", "ShieldsVPN", 0, 0, 0, 0, 0, None, None, hinst, None)
        if not self.hwnd:
            raise OSError(ctypes.get_last_error(), "CreateWindowExW failed")
        if not self._add_icon():
            raise OSError(ctypes.get_last_error(), "Shell_NotifyIconW(NIM_ADD) failed")
        user32.SetTimer(self.hwnd, self.HEALTH_TIMER, 5000, None)
        log.info("tray icon added; config %s", self.config_path)
        if self.autoconnect:
            self.connect()
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        self.loop.call_soon_threadsafe(self.loop.stop)
        for h in self._hicons.values():
            user32.DestroyIcon(h)
        log.info("tray app exited")
        return 0


def setup_logging() -> str:
    path = os.path.join(app_dir(), "pqvpn-tray.log")
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=1 << 20, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return path


def install_shortcut(config_path: str) -> list[str]:
    """Create 'ShieldsVPN' shortcuts (Desktop + Start menu) with the shield icon."""
    icon = logo.ensure_icons(os.path.join(app_dir(), "icons"))["brand"]
    target, args = windowless_python(), f'-m pqvpn tray -c "{os.path.abspath(config_path)}"'
    created = []
    for folder in ("Desktop", "Programs"):
        ps = (f"$s=(New-Object -ComObject WScript.Shell);"
              f"$d=[Environment]::GetFolderPath('{folder}');"
              f"$l=$s.CreateShortcut((Join-Path $d 'ShieldsVPN.lnk'));"
              f"$l.TargetPath='{target}';$l.Arguments='{args.replace(chr(39), chr(39) * 2)}';"
              f"$l.WorkingDirectory='{project_root()}';$l.IconLocation='{icon},0';"
              f"$l.Description='Post-quantum VPN (ML-KEM / ML-DSA)';$l.Save();(Join-Path $d 'ShieldsVPN.lnk')")
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             capture_output=True, text=True)
        if out.returncode == 0:
            path = out.stdout.strip()
            try:
                set_shortcut_app_id(path, APP_ID)
            except OSError as exc:
                log.warning("could not tag %s with the app ID: %s", path, exc)
            created.append(path)
        else:
            log.warning("shortcut in %s failed: %s", folder, out.stderr.strip())
    return created


class _PROPERTYKEY(ctypes.Structure):
    _fields_ = [("fmtid", GUID), ("pid", wt.DWORD)]


class _PROPVARIANT(ctypes.Structure):
    _fields_ = [("vt", ctypes.c_ushort), ("r1", ctypes.c_ushort), ("r2", ctypes.c_ushort), ("r3", ctypes.c_ushort),
                ("pwszVal", ctypes.c_wchar_p), ("pad", ctypes.c_void_p)]


def set_shortcut_app_id(lnk_path: str, app_id: str) -> None:
    """Write System.AppUserModel.ID into a .lnk (via IPropertyStore) so Windows attributes
    notifications from processes using that ID to this shortcut's name and icon."""
    import uuid

    ctypes.WinDLL("ole32").CoInitializeEx(None, 2)
    iid = GUID.from_buffer_copy(uuid.UUID("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99").bytes_le)  # IPropertyStore
    store = ctypes.c_void_p()
    fn = shell32.SHGetPropertyStoreFromParsingName
    fn.restype = ctypes.HRESULT
    fn.argtypes = [wt.LPCWSTR, wt.LPVOID, ctypes.c_int, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
    fn(lnk_path, None, 2, ctypes.byref(iid), ctypes.byref(store))  # GPS_READWRITE
    vtbl = ctypes.cast(store, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    set_value = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, ctypes.POINTER(_PROPERTYKEY),
                                   ctypes.POINTER(_PROPVARIANT))(vtbl[6])
    commit = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p)(vtbl[7])
    release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[2])
    key = _PROPERTYKEY(GUID.from_buffer_copy(uuid.UUID("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3").bytes_le), 5)
    value = _PROPVARIANT(vt=31, pwszVal=app_id)  # VT_LPWSTR
    try:
        set_value(store, ctypes.byref(key), ctypes.byref(value))
        commit(store)
    finally:
        release(store)


def _running_window():
    return user32.FindWindowW("pqvpnTrayWindow", "ShieldsVPN")


def _acquire_instance(replace: bool):
    """Single instance: returns a mutex handle, or None if another copy keeps running."""
    deadline = time.monotonic() + 20
    asked = False
    while True:
        handle = kernel32.CreateMutexW(None, False, "Local\\pqvpn-tray")
        if ctypes.get_last_error() != ERROR_ALREADY_EXISTS:
            return handle
        kernel32.CloseHandle(handle)
        hwnd = _running_window()
        if not replace:
            if hwnd:
                user32.PostMessageW(hwnd, user32.RegisterWindowMessageW(SHOW_MESSAGE), 0, 0)
            return None
        if hwnd and not asked:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)  # clean disconnect, then exit
            asked = True
        if time.monotonic() > deadline:
            raise RuntimeError("the running ShieldsVPN instance did not exit")
        time.sleep(0.25)


def main(config_path: str, autoconnect: bool = True, replace: bool = False) -> int:
    if not is_admin():
        if relaunch_elevated(config_path, ("--replace" if replace else "") + ("" if autoconnect else " --no-connect")):
            return 0
        user32.MessageBoxW(None, "ShieldsVPN needs Administrator rights to create its network adapter.",
                           "ShieldsVPN", 0x30)
        return 1
    try:
        shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except (AttributeError, OSError):
        pass
    setup_logging()
    try:
        mutex = _acquire_instance(replace)
    except RuntimeError as exc:
        user32.MessageBoxW(None, str(exc), "ShieldsVPN", 0x10)
        return 1
    if mutex is None:
        log.info("already running; asked the running instance to show its icon")
        return 0
    try:
        return TrayApp(config_path, autoconnect).run()
    except Exception as exc:
        log.exception("tray app failed")
        user32.MessageBoxW(None, f"ShieldsVPN could not start:\n{exc}", "ShieldsVPN", 0x10)
        return 1
