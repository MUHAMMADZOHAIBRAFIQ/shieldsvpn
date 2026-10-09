"""The pqvpn logo: one shield-and-lock design rendered as SVG (portal) and as
anti-aliased PNG/ICO images (Windows tray, shortcuts, favicon).

The raster path is pure Python: an even-odd scanline filler with 4x4
supersampling, a PNG encoder and a PNG-in-ICO container (Windows Vista+).
"""

from __future__ import annotations

import math
import os
import struct
import zlib

# state -> (top colour, bottom colour) of the shield gradient
PALETTES = {
    "brand": ((0x63, 0x66, 0xF1), (0x08, 0x91, 0xB2)),
    "connected": ((0x22, 0xC5, 0x5E), (0x15, 0x80, 0x3D)),
    "connecting": ((0xFB, 0xBF, 0x24), (0xD9, 0x77, 0x06)),
    "disconnected": ((0x94, 0xA3, 0xB8), (0x47, 0x55, 0x69)),
    "error": ((0xF8, 0x71, 0x71), (0xB9, 0x1C, 0x1C)),
}
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 256)


# ------------------------------------------------------------------ geometry (0..100 units)

def _bezier(p0, p1, p2, p3, n=32):
    out = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        out.append((u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
    return out


def _arc(cx, cy, r, a0, a1, n=24):
    return [(cx + r * math.cos(math.radians(a0 + (a1 - a0) * i / n)),
             cy + r * math.sin(math.radians(a0 + (a1 - a0) * i / n))) for i in range(n + 1)]


def _rounded_rect(x0, y0, x1, y1, r):
    return (_arc(x1 - r, y0 + r, r, -90, 0, 6) + _arc(x1 - r, y1 - r, r, 0, 90, 6)
            + _arc(x0 + r, y1 - r, r, 90, 180, 6) + _arc(x0 + r, y0 + r, r, 180, 270, 6))


SHIELD = [(50, 4), (87, 16)] + _bezier((87, 16), (87, 52), (74, 79), (50, 96))[1:] \
    + _bezier((50, 96), (26, 79), (13, 52), (13, 16))[1:]
SHACKLE = ([(35, 52)] + _arc(50, 44, 15, 180, 360) + [(65, 52), (59, 52)]
           + _arc(50, 44, 9, 360, 180) + [(41, 52)])
LOCK_BODY = _rounded_rect(31, 48, 69, 76, 4)
KEYHOLE = [_arc(50, 59, 4.5, 0, 360, 24), [(47.6, 61), (52.4, 61), (53.6, 70), (46.4, 70)]]

SVG_PATHS = {
    "shield": "M50 4 L87 16 C87 52 74 79 50 96 C26 79 13 52 13 16 Z",
    "shackle": "M35 52 V44 A15 15 0 0 1 65 44 V52 H59 V44 A9 9 0 0 0 41 44 V52 Z",
}


def svg(state: str = "brand", size: int | None = None, ident: str = "g") -> str:
    """Standalone SVG logo (also used inline in the portal)."""
    (r1, g1, b1), (r2, g2, b2) = PALETTES[state]
    dims = f' width="{size}" height="{size}"' if size else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"{dims} role="img" aria-label="pqvpn">'
            f'<defs><linearGradient id="{ident}" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="#{r1:02x}{g1:02x}{b1:02x}"/>'
            f'<stop offset="1" stop-color="#{r2:02x}{g2:02x}{b2:02x}"/></linearGradient></defs>'
            f'<path d="{SVG_PATHS["shield"]}" fill="url(#{ident})"/>'
            f'<path d="{SVG_PATHS["shackle"]}" fill="#fff"/>'
            f'<rect x="31" y="48" width="38" height="28" rx="4" fill="#fff"/>'
            f'<circle cx="50" cy="59" r="4.5" fill="url(#{ident})"/>'
            f'<path d="M47.6 61 H52.4 L53.6 70 H46.4 Z" fill="url(#{ident})"/></svg>')


# ------------------------------------------------------------------ raster

class _Raster:
    def __init__(self, size: int, ss: int = 4):
        self.size, self.ss = size, ss
        self.rgba = [[0.0, 0.0, 0.0, 0.0] for _ in range(size * size)]

    def fill(self, contours, colour_at) -> None:
        size, ss = self.size, self.ss
        S = size * ss
        k = S / 100.0
        edges = []
        for c in contours:
            pts = [(x * k, y * k) for x, y in c]
            for i, (x0, y0) in enumerate(pts):
                x1, y1 = pts[(i + 1) % len(pts)]
                if y0 != y1:
                    edges.append((x0, y0, x1, y1))
        cov = [0.0] * (size * size)
        for sy in range(S):
            yc = sy + 0.5
            xs = sorted(x0 + (yc - y0) * (x1 - x0) / (y1 - y0)
                        for x0, y0, x1, y1 in edges if min(y0, y1) <= yc < max(y0, y1))
            row = (sy // ss) * size
            for a, b in zip(xs[0::2], xs[1::2]):  # even-odd spans, in subpixels
                a, b = max(a, 0.0), min(b, float(S))
                if b <= a:
                    continue
                pa, pb = int(a // ss), int(min(b, S - 1e-9) // ss)
                if pa == pb:
                    cov[row + pa] += (b - a) / ss
                    continue
                cov[row + pa] += (ss * (pa + 1) - a) / ss
                for p in range(pa + 1, pb):
                    cov[row + p] += 1.0
                cov[row + pb] += (b - ss * pb) / ss
        for i, c in enumerate(cov):
            if c <= 0:
                continue
            a = min(c / ss, 1.0)
            r, g, b = colour_at((i // size + 0.5) / size)
            dst = self.rgba[i]
            out_a = a + dst[3] * (1 - a)
            for ch, v in enumerate((r, g, b)):
                dst[ch] = (v * a + dst[ch] * dst[3] * (1 - a)) / out_a
            dst[3] = out_a

    def png(self) -> bytes:
        size = self.size
        rows = []
        for y in range(size):
            row = bytearray(b"\x00")
            for x in range(size):
                r, g, b, a = self.rgba[y * size + x]
                row += bytes((round(r), round(g), round(b), round(a * 255)))
            rows.append(bytes(row))
        return encode_png(size, size, b"".join(rows))


def encode_png(w: int, h: int, raw_rows: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw_rows, 9)) + chunk(b"IEND", b""))


def render_png(state: str, size: int) -> bytes:
    top, bottom = PALETTES[state]

    def grad(t):
        return tuple(top[i] + (bottom[i] - top[i]) * t for i in range(3))

    def white(_t):
        return (255, 255, 255)

    r = _Raster(size, ss=4 if size <= 64 else 2)
    r.fill([SHIELD], grad)
    r.fill([SHACKLE], white)
    r.fill([LOCK_BODY], white)
    for part in KEYHOLE:  # separately: overlapping contours would cancel under even-odd
        r.fill([part], grad)
    return r.png()


def render_ico(state: str, sizes=ICO_SIZES) -> bytes:
    images = [(s, render_png(state, s)) for s in sizes]
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    blobs = b""
    for s, png in images:
        dim = 0 if s >= 256 else s
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    return out + blobs


def ensure_icons(directory: str) -> dict[str, str]:
    """Write <state>.ico for every palette into ``directory`` (cached)."""
    os.makedirs(directory, exist_ok=True)
    paths = {}
    for state in PALETTES:
        path = os.path.join(directory, f"pqvpn-{state}.ico")
        if not os.path.exists(path):
            with open(path + ".tmp", "wb") as f:
                f.write(render_ico(state))
            os.replace(path + ".tmp", path)
        paths[state] = path
    return paths
