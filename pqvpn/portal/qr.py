"""Minimal QR Code encoder (ISO/IEC 18004) -- byte mode, error-correction level M.

Used to show TOTP enrolment URIs (otpauth://...) to authenticator apps without
any third-party dependency.  Structure follows Project Nayuki's reference
implementation; verified against an independent decoder in the test-suite.
"""

from __future__ import annotations

# Level M rows of the standard tables (index = version, 0 unused)
_ECC_PER_BLOCK_M = (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
                    26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28)
_NUM_BLOCKS_M = (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
                 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49)
_FORMAT_BITS_M = 0


def _raw_modules(ver: int) -> int:
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        result -= (25 * n - 10) * n - 55
        if ver >= 7:
            result -= 36
    return result


def _data_codewords(ver: int) -> int:
    return _raw_modules(ver) // 8 - _ECC_PER_BLOCK_M[ver] * _NUM_BLOCKS_M[ver]


def _rs_mul(x: int, y: int) -> int:
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _rs_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _rs_mul(root, 0x02)
    return result


def _rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _rs_mul(coef, factor)
    return result


class QrCode:
    def __init__(self, data: bytes):
        for ver in range(1, 41):
            count_bits = 8 if ver <= 9 else 16
            if 4 + count_bits + 8 * len(data) <= _data_codewords(ver) * 8:
                break
        else:
            raise ValueError("data too long for a QR code")
        self.version = ver
        self.size = ver * 4 + 17
        self.modules = [[False] * self.size for _ in range(self.size)]
        self._func = [[False] * self.size for _ in range(self.size)]

        bits: list[int] = []

        def put(val: int, n: int):
            bits.extend((val >> i) & 1 for i in reversed(range(n)))

        put(0b0100, 4)
        put(len(data), count_bits)
        for b in data:
            put(b, 8)
        cap = _data_codewords(ver) * 8
        put(0, min(4, cap - len(bits)))
        put(0, (-len(bits)) % 8)
        pad = 0xEC
        while len(bits) < cap:
            put(pad, 8)
            pad ^= 0xEC ^ 0x11
        codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]

        self._draw_function_patterns()
        self._draw_codewords(self._interleave(codewords))
        best, best_penalty = 0, None
        for mask in range(8):
            self._apply_mask(mask)
            self._draw_format(mask)
            p = self._penalty()
            if best_penalty is None or p < best_penalty:
                best, best_penalty = mask, p
            self._apply_mask(mask)  # undo (XOR)
        self._apply_mask(best)
        self._draw_format(best)

    # -------------------------------------------------------------- drawing
    def _set(self, x: int, y: int, dark: bool) -> None:
        self.modules[y][x] = dark
        self._func[y][x] = True

    def _draw_function_patterns(self) -> None:
        size = self.size
        for i in range(size):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < size and 0 <= y < size:
                        self._set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = self._alignment_positions()
        n = len(pos)
        for i in range(n):
            for j in range(n):
                if (i, j) in ((0, 0), (0, n - 1), (n - 1, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(pos[i] + dx, pos[j] + dy, max(abs(dx), abs(dy)) != 1)
        self._draw_format(0)
        if self.version >= 7:
            rem = self.version
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            v = self.version << 12 | rem
            for i in range(18):
                bit = (v >> i) & 1 == 1
                a, b = size - 11 + i % 3, i // 3
                self._set(a, b, bit)
                self._set(b, a, bit)

    def _alignment_positions(self) -> list[int]:
        ver = self.version
        if ver == 1:
            return []
        n = ver // 7 + 2
        step = (ver * 8 + n * 3 + 5) // (n * 4 - 4) * 2
        return [6] + list(reversed([self.size - 7 - i * step for i in range(n - 1)]))

    def _draw_format(self, mask: int) -> None:
        data = _FORMAT_BITS_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 == 1  # noqa: E731
        size = self.size
        for i in range(6):
            self._set(8, i, bit(i))
        self._set(8, 7, bit(6))
        self._set(8, 8, bit(7))
        self._set(7, 8, bit(8))
        for i in range(9, 15):
            self._set(14 - i, 8, bit(i))
        for i in range(8):
            self._set(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self._set(8, size - 15 + i, bit(i))
        self._set(8, size - 8, True)

    def _interleave(self, data: list[int]) -> list[int]:
        ver = self.version
        nblocks, ecclen = _NUM_BLOCKS_M[ver], _ECC_PER_BLOCK_M[ver]
        raw = _raw_modules(ver) // 8
        nshort = nblocks - raw % nblocks
        shortlen = raw // nblocks
        div = _rs_divisor(ecclen)
        blocks, k = [], 0
        for i in range(nblocks):
            dat = data[k:k + shortlen - ecclen + (0 if i < nshort else 1)]
            k += len(dat)
            ecc = _rs_remainder(dat, div)
            if i < nshort:
                dat = dat + [0]
            blocks.append(dat + ecc)
        out = []
        for i in range(len(blocks[0])):
            for j, blk in enumerate(blocks):
                if i != shortlen - ecclen or j >= nshort:
                    out.append(blk[i])
        return out

    def _draw_codewords(self, data: list[int]) -> None:
        size, i = self.size, 0
        right = size - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = size - 1 - vert if upward else vert
                    if not self._func[y][x] and i < len(data) * 8:
                        self.modules[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    _MASKS = (
        lambda x, y: (x + y) % 2,
        lambda x, y: y % 2,
        lambda x, y: x % 3,
        lambda x, y: (x + y) % 3,
        lambda x, y: (x // 3 + y // 2) % 2,
        lambda x, y: x * y % 2 + x * y % 3,
        lambda x, y: (x * y % 2 + x * y % 3) % 2,
        lambda x, y: ((x + y) % 2 + x * y % 3) % 2,
    )

    def _apply_mask(self, mask: int) -> None:
        fn = self._MASKS[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self._func[y][x] and fn(x, y) == 0:
                    self.modules[y][x] = not self.modules[y][x]

    def _penalty(self) -> int:
        m, size, score = self.modules, self.size, 0
        for lines in (m, list(zip(*m))):  # rows, then columns (N1)
            for line in lines:
                run, prev = 0, None
                for cell in line:
                    if cell == prev:
                        run += 1
                        if run == 5:
                            score += 3
                        elif run > 5:
                            score += 1
                    else:
                        run, prev = 1, cell
        for y in range(size - 1):  # N2
            for x in range(size - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(c for row in m for c in row)  # N4
        total = size * size
        score += ((abs(dark * 20 - total * 10) + total - 1) // total - 1) * 10
        return score

    # -------------------------------------------------------------- output
    def svg(self, border: int = 4, px: int = 6) -> str:
        n = self.size + 2 * border
        path = "".join(f"M{x + border},{y + border}h1v1h-1z"
                       for y in range(self.size) for x in range(self.size) if self.modules[y][x])
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n * px}" height="{n * px}" '
                f'shape-rendering="crispEdges" role="img" aria-label="QR code">'
                f'<rect width="100%" height="100%" fill="#fff"/><path d="{path}" fill="#000"/></svg>')
