"""Strict binary encoding helpers.

Every decoder is length-checked and refuses trailing bytes: parsing is the
first thing an unauthenticated packet touches, so it must be boring.
"""

from __future__ import annotations

import struct


class DecodeError(ValueError):
    pass


class Writer:
    __slots__ = ("parts",)

    def __init__(self):
        self.parts: list[bytes] = []

    def u8(self, v: int) -> "Writer":
        self.parts.append(struct.pack(">B", v))
        return self

    def u16(self, v: int) -> "Writer":
        self.parts.append(struct.pack(">H", v))
        return self

    def u32(self, v: int) -> "Writer":
        self.parts.append(struct.pack(">I", v))
        return self

    def u64(self, v: int) -> "Writer":
        self.parts.append(struct.pack(">Q", v))
        return self

    def raw(self, b: bytes) -> "Writer":
        self.parts.append(bytes(b))
        return self

    def vec8(self, b: bytes) -> "Writer":
        if len(b) > 0xFF:
            raise ValueError("vec8 overflow")
        return self.u8(len(b)).raw(b)

    def vec16(self, b: bytes) -> "Writer":
        if len(b) > 0xFFFF:
            raise ValueError("vec16 overflow")
        return self.u16(len(b)).raw(b)

    def vec32(self, b: bytes) -> "Writer":
        return self.u32(len(b)).raw(b)

    def bytes(self) -> bytes:
        return b"".join(self.parts)


class Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes):
        self.buf = memoryview(bytes(buf))
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.buf):
            raise DecodeError("truncated")
        out = self.buf[self.pos:self.pos + n].tobytes()
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec32(self, limit: int = 1 << 20) -> bytes:
        n = self.u32()
        if n > limit:
            raise DecodeError("vector too long")
        return self.take(n)

    def remaining(self) -> int:
        return len(self.buf) - self.pos

    def done(self) -> None:
        if self.remaining():
            raise DecodeError("trailing bytes")
