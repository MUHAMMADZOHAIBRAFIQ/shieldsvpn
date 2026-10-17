"""Find committed or packaged secrets (paths and types only -- values are never printed).

    python tools/secret_scan.py                 # files `git add -A` would include (tracked + untracked, not ignored)
    python tools/secret_scan.py app-debug.apk   # every entry inside an APK / ZIP
    python tools/secret_scan.py some/dir file   # explicit files or directories

Exit status 1 if anything is found.  Detects real key material, not mentions of it: a PEM header with no
base64 body (e.g. a placeholder in documentation or a test assertion) is not reported.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import zipfile

PEM_PRIVATE = re.compile(rb"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----\r?\n([A-Za-z0-9+/=]{40,}\r?\n)")
SERVICE_ACCOUNT = re.compile(rb'"type"\s*:\s*"service_account".{0,4000}?"private_key"\s*:\s*'
                             rb'"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\n)[A-Za-z0-9+/=]{40,}', re.S)
PSK_LINE = re.compile(rb"^\s*[A-Za-z0-9+/]{43}=\s*$")  # exactly a base64-encoded 32-byte key (pqvpn genpsk)
VAULT_SEAL = re.compile(rb"enc:v1:[A-Za-z0-9+/=]{40,}")
SECRET_NAMES = re.compile(r"(^|/)(psk\.key|portal-secrets\.key|keystore\.properties|firebase-key[^/]*\.json)$|"
                          r"\.(jks|keystore|db|db-wal)$", re.I)
MAX_BYTES = 8 << 20


def classify(name: str, data: bytes) -> list[str]:
    found = []
    m = PEM_PRIVATE.search(data)
    if m:
        found.append(f"PEM {m.group(1).decode()} with key material")
    if SERVICE_ACCOUNT.search(data):
        found.append("Google service-account key")
    if os.path.basename(name).lower().endswith(".key") and PSK_LINE.match(data):
        found.append("pre-shared key (32-byte base64)")
    if VAULT_SEAL.search(data) and not name.endswith((".py", ".md", ".kt", ".ts", ".tsx")):
        found.append("vault-sealed secret value")
    if SECRET_NAMES.search(name.replace(os.sep, "/")):
        found.append("file type that holds secrets")
    if data[:16] == b"SQLite format 3\x00":
        found.append("SQLite database")
    return found


def scan_archive(path: str) -> list[tuple[str, list[str]]]:
    out = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir() or info.file_size > MAX_BYTES:
                continue
            name = f"{path}!/{info.filename}"
            data = z.read(info)
            if info.filename.endswith((".imy", ".zip")):  # Chaquopy packs Python sources as nested ZIPs
                try:
                    import io
                    with zipfile.ZipFile(io.BytesIO(data)) as inner:
                        for ii in inner.infolist():
                            if not ii.is_dir() and ii.file_size <= MAX_BYTES:
                                hits = classify(ii.filename, inner.read(ii))
                                if hits:
                                    out.append((f"{name}!/{ii.filename}", hits))
                except zipfile.BadZipFile:
                    pass
                continue
            hits = classify(info.filename, data)
            if hits:
                out.append((name, hits))
    return out


def candidate_files() -> list[str]:
    res = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                         capture_output=True, check=True)
    return [p for p in res.stdout.decode("utf-8", "replace").split("\0") if p]


def scan_paths(paths: list[str]) -> list[tuple[str, list[str]]]:
    findings = []
    for p in paths:
        if os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in (".git", "node_modules", "build", ".gradle")]
                findings += scan_paths([os.path.join(dp, f) for f in fn])
            continue
        if not os.path.isfile(p) or os.path.getsize(p) > MAX_BYTES:
            continue
        if p.lower().endswith((".apk", ".aab", ".zip")) and zipfile.is_zipfile(p):
            findings += scan_archive(p)
            continue
        with open(p, "rb") as f:
            hits = classify(p, f.read())
        if hits:
            findings.append((p, hits))
    return findings


def main(argv: list[str]) -> int:
    paths = argv or candidate_files()
    findings = scan_paths(paths)
    for path, hits in findings:
        print(f"SECRET  {path}: {', '.join(hits)}")
    print(f"secret_scan: {len(findings)} finding(s) in {len(paths)} path(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
