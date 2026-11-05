#!/usr/bin/env bash
# Prepare a ShieldsVPN host on Debian 13 (trixie).  Safe to rerun.
#
#   sudo REPO=https://github.com/MUHAMMADZOHAIBRAFIQ/shieldsvpn.git BRANCH=main bash setup.sh
#
# This only prepares the machine (packages, user, code, forwarding, firewall, service units).  It does NOT create
# the PKI, write any secret, or start anything public -- that is `pqvpn portal-init` plus a TLS certificate, which
# you run once by hand (see docs/DEPLOY.md).  Nothing here is destructive except the ufw rule set, which it
# re-applies to a known state every run.
set -euo pipefail

CODE=/opt/shieldsvpn
DATA=/var/lib/pqvpn
REPO=${REPO:-https://github.com/MUHAMMADZOHAIBRAFIQ/shieldsvpn.git}
BRANCH=${BRANCH:-main}
PUB_IFACE=${PUB_IFACE:-$(ip -o -4 route show to default | awk '{print $5; exit}')}

[ "$(id -u)" = 0 ] || { echo "run as root (sudo bash setup.sh)"; exit 1; }

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends python3 git nodejs npm ufw ca-certificates curl >/dev/null
echo "   OpenSSL: $(openssl version)"
echo "   Python : $(python3 --version)"
echo "   Node   : $(node --version 2>/dev/null || echo 'missing (email will be off)')"
python3 - <<'PY'
import ssl, sys
if ssl.OPENSSL_VERSION_INFO < (3, 5):
    sys.stderr.write("\n   !! system OpenSSL is older than 3.5: pqvpn needs >= 3.5. Build it and set\n"
                     "      PQVPN_LIBCRYPTO in the two service units before starting.\n\n")
PY

echo "== user and data dir ($DATA, owned by pqvpn, 0700)"
id -u pqvpn >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin pqvpn
install -d -o pqvpn -g pqvpn -m 700 "$DATA"

echo "== code at $CODE (branch $BRANCH)"
if [ -d "$CODE/.git" ]; then
    git -C "$CODE" fetch --depth 1 origin "$BRANCH"
    git -C "$CODE" checkout -q -f FETCH_HEAD
else
    git clone --depth 1 -b "$BRANCH" "$REPO" "$CODE"
fi

echo "== Nodemailer dependencies (for password-reset / verification email)"
if command -v npm >/dev/null; then
    ( cd "$CODE/pqvpn/portal/mailer" && npm ci --omit=dev --no-audit --no-fund >/dev/null ) \
        && echo "   installed" || echo "   npm install failed; email stays off until fixed"
fi

echo "== IP forwarding (needed for NAT / full tunnel)"
cat >/etc/sysctl.d/99-pqvpn.conf <<'SYS'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
SYS
sysctl -q --system

echo "== firewall (ufw): SSH, portal 443/tcp, VPN 51820/udp, stealth 443/udp; everything else denied"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow OpenSSH >/dev/null
ufw allow 443/tcp  >/dev/null   # portal (TLS)
ufw allow 51820/udp >/dev/null  # VPN
ufw allow 443/udp  >/dev/null   # stealth-mode VPN listener (optional)
# The VPN authenticates its own clients, so forwarded tunnel traffic is allowed to pass:
sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
ufw --force enable >/dev/null

echo "== service units"
install -m 644 "$CODE/deploy/pqvpn-server.service" /etc/systemd/system/pqvpn-server.service
install -m 644 "$CODE/deploy/pqvpn-portal.service" /etc/systemd/system/pqvpn-portal.service
systemctl daemon-reload

cat <<DONE

Host prepared. Public interface detected: ${PUB_IFACE:-unknown}

NEXT (once, by hand -- see docs/DEPLOY.md). Nothing is live until you do this:
  1. Point an A/AAAA record at this droplet, e.g. vpn.YOURDOMAIN.
  2. Create the PKI, configs and first admin (as the pqvpn user), with stealth on:
       sudo -u pqvpn python3 -m pqvpn portal-init --data $DATA \\
            --server-name vpn.YOURDOMAIN --endpoint vpn.YOURDOMAIN:51820 \\
            --public-url https://vpn.YOURDOMAIN --listen 0.0.0.0:443 \\
            --nat-interface ${PUB_IFACE:-eth0} --stealth
  3. Get a TLS certificate and point portal.toml at it (certbot; see the guide).
  4. systemctl enable --now pqvpn-server pqvpn-portal
  5. Read the "before you go live" gates in docs/DEPLOY.md (abuse policy, CA key, backups).
DONE
