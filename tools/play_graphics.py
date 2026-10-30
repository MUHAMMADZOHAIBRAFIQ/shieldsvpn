"""Google Play store graphics for ShieldsVPN, and a length check of the store listing.

    python tools/play_graphics.py                  # writes docs/play-store/graphics/{icon-512,feature-graphic}.png
    python tools/play_graphics.py --check-listing  # app name <= 30, short description <= 80, full <= 4000 characters

The icon is drawn by pqvpn/logo.py (512 x 512, opaque 32-bit PNG).  The feature graphic (1024 x 500, PNG without
transparency) has text, so it is rendered by a local headless Chrome or Edge ($CHROME overrides the path).
Screenshots are not made here: they must show the real app (docs/play-store/README.md, step 4).
"""

from __future__ import annotations

import argparse
import html
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "play-store", "graphics")
LISTING = os.path.join(ROOT, "docs", "play-store", "STORE_LISTING.md")
BACKGROUND = (11, 16, 32)  # the app's background colour, #0b1020
LIMITS = {"App name": 30, "Short description": 80, "Full description": 4000}
BROWSERS = (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "/usr/bin/google-chrome", "/usr/bin/chromium")

sys.path.insert(0, ROOT)

FEATURE_HTML = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;width:1024px;height:500px;overflow:hidden}}
body{{background:radial-gradient(900px 500px at 78% 10%,#1e1b4b 0%,transparent 60%),linear-gradient(160deg,#0b1020,#0f172a);
color:#e2e8f0;font-family:"Segoe UI",system-ui,sans-serif;display:flex;align-items:center;gap:56px;padding:0 84px;
box-sizing:border-box}}
svg{{width:220px;height:220px;flex:none;filter:drop-shadow(0 18px 40px rgba(34,211,238,.25))}}
h1{{margin:0 0 14px;font-size:70px;letter-spacing:-1px}} h1 b{{color:#22d3ee}}
p{{margin:0;font-size:31px;color:#cbd5e1;line-height:1.35}}
.tags{{margin-top:26px;display:flex;gap:12px}}
.tags span{{border:1px solid #334155;border-radius:999px;padding:6px 16px;font-size:20px;color:#a5b4fc}}
</style></head><body>{logo}<div><h1>Shields<b>VPN</b></h1><p>{tagline}</p>
<div class="tags"><span>ML-KEM</span><span>ML-DSA</span><span>One tap</span></div></div></body></html>"""


def png_info(data: bytes) -> tuple[int, int, int]:
    """(width, height, colour type) of a PNG."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    w, h = struct.unpack(">II", data[16:24])
    return w, h, data[25]


def browser() -> str:
    for path in (os.environ.get("CHROME", ""), *BROWSERS):
        if path and os.path.isfile(path):
            return path
    raise SystemExit("no Chrome or Edge found; set CHROME to its path")


def feature_graphic(path: str) -> None:
    from pqvpn import logo
    page = FEATURE_HTML.format(logo=logo.svg("brand", ident="fg"),
                               tagline=html.escape("Post-quantum VPN.<br>One tap to protect your connection.")
                               .replace("&lt;br&gt;", "<br>"))
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "feature.html")
        with open(src, "w", encoding="utf-8") as f:
            f.write(page)
        subprocess.run([browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
                        "--force-device-scale-factor=1", "--window-size=1024,500", f"--screenshot={path}",
                        "file:///" + src.replace(os.sep, "/")], capture_output=True, timeout=120, check=False)
    with open(path, "rb") as f:
        w, h, kind = png_info(f.read())
    if (w, h) != (1024, 500) or kind != 2:  # 2 = RGB without alpha, as Play requires
        raise SystemExit(f"feature graphic came out {w}x{h}, colour type {kind}; Play needs 1024x500 RGB")


def check_listing() -> int:
    with open(LISTING, encoding="utf-8") as f:
        text = f.read()
    bad = 0
    for title, limit in LIMITS.items():
        m = re.search(rf"## {title}\n\n```text\n(.*?)\n```", text, re.S)
        if not m:
            print(f"{title}: not found in {LISTING}")
            bad += 1
            continue
        n = len(m.group(1))
        print(f"{title}: {n} / {limit} characters" + ("  TOO LONG" if n > limit else ""))
        bad += n > limit
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--check-listing", action="store_true")
    p.add_argument("--out", default=OUT)
    args = p.parse_args(argv)
    if args.check_listing:
        return check_listing()
    from pqvpn import logo
    os.makedirs(args.out, exist_ok=True)
    icon = os.path.join(args.out, "icon-512.png")
    with open(icon, "wb") as f:
        f.write(logo.render_tile("brand", 512, BACKGROUND))
    feature = os.path.join(args.out, "feature-graphic.png")
    feature_graphic(feature)
    for path in (icon, feature):
        with open(path, "rb") as f:
            w, h, kind = png_info(f.read())
        print(f"{path}: {w}x{h}, {'RGBA' if kind == 6 else 'RGB'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
