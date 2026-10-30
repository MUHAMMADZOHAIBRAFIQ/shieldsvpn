"""Build the ShieldsVPN browser extension for the extension stores.

    python tools/build_extension.py [--firefox-id companion@shieldsvpn.app] [--out browser-extension/dist]

Writes ``chromium/`` (Chrome Web Store, Microsoft Edge Add-ons, Opera add-ons; Brave uses the Chrome Web Store) and
``firefox/`` (addons.mozilla.org) folders plus one ZIP per store.  Icons are rendered from the ShieldsVPN logo
(pqvpn/logo.py), so no image files are kept in the repository.  Load ``dist/chromium`` with "Load unpacked" to test.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "browser-extension")
FILES = ("popup.html", "popup.css", "popup.js")
ICON_SIZES = (16, 32, 48, 128)

sys.path.insert(0, ROOT)


def build(out: str, firefox_id: str) -> list[str]:
    from pqvpn import logo
    from pqvpn.native_host import FIREFOX_ID_RE

    if not FIREFOX_ID_RE.match(firefox_id):
        raise SystemExit(f"{firefox_id!r} is not a valid Firefox add-on id")
    with open(os.path.join(SRC, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    variants = {
        "chromium": manifest,
        "firefox": {**{k: v for k, v in manifest.items() if k != "minimum_chrome_version"},
                    "browser_specific_settings": {"gecko": {
                        "id": firefox_id, "strict_min_version": "115.0",
                        # addons.mozilla.org asks every add-on to declare what it collects: nothing.
                        "data_collection_permissions": {"required": ["none"]}}}},
    }
    built = []
    for name, data in variants.items():
        d = os.path.join(out, name)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(os.path.join(d, "icons"))
        for fname in FILES:
            shutil.copyfile(os.path.join(SRC, fname), os.path.join(d, fname))
        for size in ICON_SIZES:
            with open(os.path.join(d, "icons", f"icon-{size}.png"), "wb") as f:
                f.write(logo.render_png("brand", size))
        with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        archive = os.path.join(out, f"shieldsvpn-extension-{name}-{manifest['version']}.zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for dp, _dn, fn in os.walk(d):
                for f2 in sorted(fn):
                    full = os.path.join(dp, f2)
                    z.write(full, os.path.relpath(full, d).replace(os.sep, "/"))
        built += [d, archive]
    return built


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--firefox-id", default="companion@shieldsvpn.app")
    p.add_argument("--out", default=os.path.join(SRC, "dist"))
    args = p.parse_args(argv)
    for path in build(os.path.abspath(args.out), args.firefox_id):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
