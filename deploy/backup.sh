#!/usr/bin/env bash
# Back up the ShieldsVPN portal database and the secrets that decrypt it.  Safe to rerun; makes one dated archive.
#
#   sudo bash backup.sh [/destination/dir]        # default: /var/backups/shieldsvpn
#   RESTORE=/path/to/shieldsvpn-YYYYMMDD-HHMMSS.tar.gz sudo bash backup.sh --restore
#
# What it saves: a consistent copy of portal.db (via SQLite's online backup, so it is safe while the portal runs),
# portal-secrets.key (the vault key that decrypts the SMTP/Paddle/2FA secrets), the CA certificate, and the configs.
# It deliberately does NOT include ca.key by default (your offline root key) -- keep that backed up separately.
#
# The archive contains secrets.  Encrypt it before it leaves the server: set GPG_RECIPIENT to a GPG key id (or
# PASSPHRASE for symmetric), and the output becomes <name>.tar.gz.gpg.  Store it off the server (e.g. object storage).
set -euo pipefail

DATA=/var/lib/pqvpn
DEST=${1:-/var/backups/shieldsvpn}
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

if [ "${1:-}" = "--restore" ]; then
    : "${RESTORE:?set RESTORE=/path/to/archive.tar.gz(.gpg)}"
    echo "Restoring from $RESTORE into $DATA"
    systemctl stop pqvpn-portal pqvpn-server 2>/dev/null || true
    tmp=$(mktemp -d)
    if [[ "$RESTORE" == *.gpg ]]; then gpg -o "$tmp/a.tar.gz" -d "$RESTORE"; else cp "$RESTORE" "$tmp/a.tar.gz"; fi
    tar -xzf "$tmp/a.tar.gz" -C "$tmp"
    install -o pqvpn -g pqvpn -m 600 "$tmp"/*/portal.db "$DATA/portal.db"
    install -o pqvpn -g pqvpn -m 600 "$tmp"/*/portal-secrets.key "$DATA/portal-secrets.key"
    rm -rf "$tmp"
    echo "Restored. Review configs, then: systemctl start pqvpn-server pqvpn-portal"
    exit 0
fi

mkdir -p "$DEST"
stamp=$(date -u +%Y%m%d-%H%M%S)
work=$(mktemp -d)
out="$work/shieldsvpn-$stamp"
mkdir -p "$out"

# Consistent DB snapshot even while the portal is writing (WAL): use SQLite's .backup, not cp.
sqlite3 "$DATA/portal.db" ".backup '$out/portal.db'"
cp "$DATA/portal-secrets.key" "$out/portal-secrets.key"
[ -f "$DATA/ca/ca.crt" ] && install -D "$DATA/ca/ca.crt" "$out/ca/ca.crt"
for f in portal.toml server.toml; do [ -f "$DATA/$f" ] && cp "$DATA/$f" "$out/"; done

archive="$DEST/shieldsvpn-$stamp.tar.gz"
tar -C "$work" -czf "$archive" "shieldsvpn-$stamp"
chmod 600 "$archive"

if [ -n "${GPG_RECIPIENT:-}" ]; then
    gpg --yes --trust-model always -r "$GPG_RECIPIENT" -o "$archive.gpg" -e "$archive" && rm -f "$archive"
    archive="$archive.gpg"
elif [ -n "${PASSPHRASE:-}" ]; then
    gpg --yes --batch --passphrase "$PASSPHRASE" -c -o "$archive.gpg" "$archive" && rm -f "$archive"
    archive="$archive.gpg"
else
    echo "WARNING: archive is NOT encrypted. Set GPG_RECIPIENT or PASSPHRASE, and move it off the server."
fi
rm -rf "$work"

# Keep the last 14 archives.
ls -1t "$DEST"/shieldsvpn-*.tar.gz* 2>/dev/null | tail -n +15 | xargs -r rm -f
echo "Backup: $archive"
echo "Copy it OFF this server (the database and the key must not be lost with the droplet)."
