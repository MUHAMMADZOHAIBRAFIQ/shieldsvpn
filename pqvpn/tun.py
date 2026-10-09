"""Layer-3 TUN devices.

  * Linux:   /dev/net/tun (IFF_TUN | IFF_NO_PI), driven by the event loop.
  * Windows: Wintun (https://www.wintun.net, the driver WireGuard uses).  Put
             the signed ``wintun.dll`` for your architecture next to this
             package, in the working directory, or point $PQVPN_WINTUN at it.
  * MemoryTun: in-process device for tests and loopback self-tests.

Every device delivers *batches* of raw IP packets to ``on_packets`` on the
event-loop thread and accepts raw IP packets via ``write``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import sys
import threading
from typing import Callable

log = logging.getLogger("pqvpn.tun")
PacketSink = Callable[[list[bytes]], None]


class MemoryTun:
    """In-memory TUN used by tests: ``inject`` = packets 'from the OS'."""

    def __init__(self, name: str = "mem0", mtu: int = 1420):
        self.name, self.mtu = name, mtu
        self.written: asyncio.Queue[bytes] = asyncio.Queue()
        self._sink: PacketSink | None = None

    def start(self, loop: asyncio.AbstractEventLoop, on_packets: PacketSink) -> None:
        self._sink = on_packets

    def inject(self, packet: bytes) -> None:
        assert self._sink is not None
        self._sink([packet])

    def write(self, packet: bytes) -> None:
        self.written.put_nowait(packet)

    def close(self) -> None:
        self._sink = None


# ---------------------------------------------------------------- Linux

class LinuxTun:
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, name: str, mtu: int):
        import fcntl

        self.mtu = mtu
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        try:
            ifr = struct.pack("16sH22x", name.encode(), self.IFF_TUN | self.IFF_NO_PI)
            res = fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
        except OSError:
            os.close(self.fd)
            raise
        self.name = res[:16].rstrip(b"\0").decode()
        os.set_blocking(self.fd, False)
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self, loop: asyncio.AbstractEventLoop, on_packets: PacketSink) -> None:
        self._loop, self._sink = loop, on_packets
        loop.add_reader(self.fd, self._readable)

    def _readable(self) -> None:
        batch = []
        for _ in range(128):
            try:
                pkt = os.read(self.fd, 65535)
            except (BlockingIOError, InterruptedError):
                break
            if not pkt:
                break
            batch.append(pkt)
        if batch:
            self._sink(batch)

    def write(self, packet: bytes) -> None:
        try:
            os.write(self.fd, packet)
        except (BlockingIOError, OSError) as exc:
            log.debug("tun write dropped: %s", exc)

    def close(self) -> None:
        if self._loop is not None:
            self._loop.remove_reader(self.fd)
            self._loop = None
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


# ---------------------------------------------------------------- Windows

class WintunTun:
    RING_CAPACITY = 0x400000  # 4 MiB
    ERROR_NO_MORE_ITEMS = 259
    ERROR_HANDLE_EOF = 38

    def __init__(self, name: str, mtu: int):
        import ctypes
        import uuid
        from ctypes import POINTER, byref, c_ubyte, c_uint32, c_uint64, c_void_p, c_wchar_p, wintypes

        self.ctypes = ctypes
        self.name, self.mtu = name, mtu
        dll = ctypes.WinDLL(_find_wintun(), use_last_error=True)

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", c_uint32), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                        ("Data4", c_ubyte * 8)]

        sigs = {
            "WintunCreateAdapter": (c_void_p, [c_wchar_p, c_wchar_p, POINTER(GUID)]),
            "WintunOpenAdapter": (c_void_p, [c_wchar_p]),
            "WintunCloseAdapter": (None, [c_void_p]),
            "WintunGetAdapterLUID": (None, [c_void_p, POINTER(c_uint64)]),
            "WintunGetRunningDriverVersion": (wintypes.DWORD, []),
            "WintunStartSession": (c_void_p, [c_void_p, wintypes.DWORD]),
            "WintunEndSession": (None, [c_void_p]),
            "WintunGetReadWaitEvent": (wintypes.HANDLE, [c_void_p]),
            "WintunReceivePacket": (c_void_p, [c_void_p, POINTER(wintypes.DWORD)]),
            "WintunReleaseReceivePacket": (None, [c_void_p, c_void_p]),
            "WintunAllocateSendPacket": (c_void_p, [c_void_p, wintypes.DWORD]),
            "WintunSendPacket": (None, [c_void_p, c_void_p]),
        }
        for fn, (res, args) in sigs.items():
            f = getattr(dll, fn)
            f.restype, f.argtypes = res, args
        self.dll = dll
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateEventW.restype = wintypes.HANDLE
        k32.CreateEventW.argtypes = [c_void_p, wintypes.BOOL, wintypes.BOOL, c_wchar_p]
        k32.SetEvent.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.WaitForMultipleObjects.restype = wintypes.DWORD
        k32.WaitForMultipleObjects.argtypes = [wintypes.DWORD, POINTER(wintypes.HANDLE), wintypes.BOOL,
                                               wintypes.DWORD]
        self.k32 = k32

        stale = dll.WintunOpenAdapter(name)
        if stale:  # left over from a crashed run
            dll.WintunCloseAdapter(stale)
        # A stable GUID per name lets Windows reuse one network profile.
        guid = GUID.from_buffer_copy(uuid.uuid5(uuid.NAMESPACE_URL, f"pqvpn:{name}").bytes_le)
        self.adapter = dll.WintunCreateAdapter(name, "pqvpn", byref(guid))
        if not self.adapter:
            raise OSError(ctypes.get_last_error(), "WintunCreateAdapter failed (run as Administrator?)")
        luid = c_uint64()
        dll.WintunGetAdapterLUID(self.adapter, byref(luid))
        idx = wintypes.ULONG()
        ctypes.WinDLL("iphlpapi").ConvertInterfaceLuidToIndex(byref(luid), byref(idx))
        self.if_index = idx.value
        self.session = dll.WintunStartSession(self.adapter, self.RING_CAPACITY)
        if not self.session:
            err = ctypes.get_last_error()
            dll.WintunCloseAdapter(self.adapter)
            raise OSError(err, "WintunStartSession failed")
        self.read_event = dll.WintunGetReadWaitEvent(self.session)
        self.quit_event = k32.CreateEventW(None, True, False, None)
        self._thread: threading.Thread | None = None
        self._closed = False
        log.info("Wintun driver %d.%d, adapter %s (ifIndex %d)",
                 (v := dll.WintunGetRunningDriverVersion()) >> 16, v & 0xFFFF, name, self.if_index)

    def start(self, loop: asyncio.AbstractEventLoop, on_packets: PacketSink) -> None:
        self._thread = threading.Thread(target=self._reader, args=(loop, on_packets),
                                        name="wintun-rx", daemon=True)
        self._thread.start()

    def _reader(self, loop, on_packets) -> None:
        ctypes, dll = self.ctypes, self.dll
        from ctypes import byref, wintypes

        size = wintypes.DWORD()
        handles = (wintypes.HANDLE * 2)(self.read_event, self.quit_event)
        while not self._closed:
            batch = []
            while len(batch) < 128:
                p = dll.WintunReceivePacket(self.session, byref(size))
                if not p:
                    err = ctypes.get_last_error()
                    if err == self.ERROR_NO_MORE_ITEMS:
                        break
                    if not self._closed:
                        log.error("Wintun receive failed (error %d); adapter gone?", err)
                    return
                batch.append(ctypes.string_at(p, size.value))
                dll.WintunReleaseReceivePacket(self.session, p)
            if batch:
                loop.call_soon_threadsafe(on_packets, batch)
                continue
            self.k32.WaitForMultipleObjects(2, handles, False, 0xFFFFFFFF)

    def write(self, packet: bytes) -> None:
        p = self.dll.WintunAllocateSendPacket(self.session, len(packet))
        if not p:  # ring full: drop, like a congested link
            return
        self.ctypes.memmove(p, packet, len(packet))
        self.dll.WintunSendPacket(self.session, p)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.k32.SetEvent(self.quit_event)
        if self._thread:
            self._thread.join(timeout=2)
        self.dll.WintunEndSession(self.session)
        self.dll.WintunCloseAdapter(self.adapter)
        self.k32.CloseHandle(self.quit_event)


def _find_wintun() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.environ.get("PQVPN_WINTUN", ""), os.path.join(here, "wintun.dll"),
                  os.path.join(os.path.dirname(here), "wintun.dll"), os.path.join(os.getcwd(), "wintun.dll")]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    raise FileNotFoundError(
        "wintun.dll not found. Download it from https://www.wintun.net/ (signed by WireGuard LLC), "
        "and copy bin/<arch>/wintun.dll next to pqvpn/ or set PQVPN_WINTUN.")


def open_tun(name: str, mtu: int):
    if sys.platform.startswith("linux"):
        return LinuxTun(name, mtu)
    if sys.platform == "win32":
        return WintunTun(name, mtu)
    raise NotImplementedError(f"TUN not implemented for {sys.platform} (Linux and Windows are supported)")
