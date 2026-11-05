# Production deployment (DigitalOcean) and disaster recovery

A step-by-step for putting ShieldsVPN on a single DigitalOcean droplet, with rollback and recovery. It targets
**Debian 13 (trixie)**, which ships OpenSSL 3.5 and Python 3.13, so ShieldsVPN runs natively with no special build.

> **Status: prepared, not yet run on a real droplet.** The scripts (`deploy/setup.sh`, `deploy/backup.sh`) and the
> service units were written against the documented behaviour but have not been executed on a live host. Run them on
> a throwaway droplet first and fix anything that differs before using them for real. Nothing here was tested
> end-to-end on DigitalOcean.

## 0. Decide these before you spend money or go public

| Gate | Why |
| --- | --- |
| **Abuse policy in writing.** Email DigitalOcean (abuse@digitalocean.com / support) and confirm a public VPN exit node is allowed and how they handle complaints. | DigitalOcean allows self-run VPNs, but **you are responsible for all traffic that leaves your droplet**, and they can suspend the droplet on abuse complaints (copyright, spam, scanning). |
| **A domain name.** You need one (e.g. `vpn.example.com`) for a trusted TLS certificate and for the apps to connect without pinning. | Let's Encrypt issues for domains, not bare IPs. |
| **The CA-key risk (audit finding C1).** Today the portal keeps the root CA private key online to issue profiles, and that same CA signs the server certificate. A droplet compromise could mint a server certificate. | Acceptable for a beta; before scale, split to an offline root + online device CA (AUDIT-2026-11.md §5.1). Decide whether to launch the beta with this risk documented. |
| **Censorship reality.** The droplet's IP is a data-centre IP that the strictest censors block wholesale. Stealth mode (below) defeats traffic fingerprinting, **not** IP-range blocks. | Set expectations for users in heavily censored countries. |

Do not go to step 1 until the first two gates are cleared.

## 1. Create the droplet

- Image **Debian 13 x64**, region **Amsterdam (AMS3)** (see the hosting note: avoid US adult-ID-check states, UK,
  Germany, India), size **2 GB / 2 vCPU** or larger (the data plane is one core — see the benchmark in
  AUDIT-2026-11.md §6 for how many users that holds), IPv4 **and** IPv6 enabled, add your SSH key.
- In the DigitalOcean control panel, a Cloud Firewall is optional — `setup.sh` configures the host firewall (ufw)
  with the same rules. If you use both, open: SSH (22/tcp), 443/tcp, 51820/udp, 443/udp.

## 2. DNS

Point records at the droplet's addresses (replace the domain):

```text
A     vpn.example.com     <droplet IPv4>
AAAA  vpn.example.com     <droplet IPv6>
```

Wait for them to resolve (`dig +short vpn.example.com`).

## 3. Prepare the host (safe to rerun)

```bash
ssh root@<droplet IP>
curl -fsSL https://raw.githubusercontent.com/MUHAMMADZOHAIBRAFIQ/shieldsvpn/main/deploy/setup.sh -o setup.sh
# read it first, then:
REPO=https://github.com/MUHAMMADZOHAIBRAFIQ/shieldsvpn.git BRANCH=main bash setup.sh
```

It installs packages, creates the `pqvpn` user and `/var/lib/pqvpn`, clones the code to `/opt/shieldsvpn`, installs
the Nodemailer deps, enables IP forwarding, sets the firewall, and installs the two systemd units. It does **not**
create any key or start anything.

## 4. Create the PKI, configs and the first admin (once)

Run as the `pqvpn` user so the database is owned correctly. `--stealth` turns on the obfuscation layer and copies its
key into every profile; `--nat-interface` is the droplet's public interface (`setup.sh` printed it, usually `eth0`).

```bash
sudo -u pqvpn python3 -m pqvpn portal-init --data /var/lib/pqvpn \
     --server-name vpn.example.com --endpoint vpn.example.com:51820 \
     --public-url https://vpn.example.com --listen 0.0.0.0:443 \
     --nat-interface eth0 --stealth --admin youradmin
```

It prints a one-time admin password — save it. Keep `/var/lib/pqvpn/ca/ca.key` safe; for a stronger setup, move it
offline after issuance (the portal needs it only to issue/renew profiles).

## 5. TLS certificate (Let's Encrypt)

The portal listens on 443 and refuses plain HTTP on a public address, so give it a real certificate. Use certbot in
standalone mode (it needs port 80 briefly; ufw already allows outbound, open 80 for the challenge):

```bash
apt-get install -y certbot
ufw allow 80/tcp
certbot certonly --standalone -d vpn.example.com --agree-tos -m you@example.com --non-interactive
ufw delete allow 80/tcp
```

Point the portal at the cert (it reads them live) and let its user read them — the unit already allows
`/etc/letsencrypt`:

```bash
sudo -u pqvpn sed -i \
  -e 's#^# tls_certificate =.*#tls_certificate = "/etc/letsencrypt/live/vpn.example.com/fullchain.pem"#' \
  -e 's#^# tls_private_key =.*#tls_private_key = "/etc/letsencrypt/live/vpn.example.com/privkey.pem"#' \
  /var/lib/pqvpn/portal.toml
```

Auto-renew and reload the portal on renewal:

```bash
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nsystemctl reload-or-restart pqvpn-portal\n' \
  > /etc/letsencrypt/renewal-hooks/deploy/pqvpn.sh
chmod +x /etc/letsencrypt/renewal-hooks/deploy/pqvpn.sh
```

## 6. Start

```bash
systemctl enable --now pqvpn-server pqvpn-portal
systemctl status pqvpn-server pqvpn-portal --no-pager
journalctl -u pqvpn-server -n 30 --no-pager
```

## 7. Verify (do each, don't assume)

- **Portal**: open `https://vpn.example.com/` — valid certificate, sign-in page. Sign in with the admin password,
  set 2FA. Turn on app features in Settings only as you need them (they default off).
- **VPN handshake + internet**: on a test client, import a profile (or, for the apps, point `deploy.properties`
  `portalUrl` at `https://vpn.example.com/`, build, enroll) and connect. Confirm you reach the internet through the
  tunnel and that DNS resolves (full-tunnel needs a pushed DNS server, or the Android app refuses — by design).
- **Firewall**: from outside, confirm only 22/443-tcp and 51820/443-udp answer.
- **Stealth**: a client with the obfuscation key connects; without it (or on the plain port) it does not.
- Record what you tested in AUDIT-2026-11.md §7.

## 8. Backups (do this before you have real users)

```bash
# nightly, encrypted to a GPG key you hold, kept off the droplet too:
echo '15 3 * * * root GPG_RECIPIENT=<your-key-id> bash /opt/shieldsvpn/deploy/backup.sh' \
  > /etc/cron.d/shieldsvpn-backup
```

Copy the archives off the server (DigitalOcean Spaces or elsewhere). The backup holds `portal.db` and
`portal-secrets.key`; losing either loses accounts or the ability to read the sealed secrets. Keep `ca.key` backed up
separately and offline.

## 9. Rollback and disaster recovery

| Situation | Action |
| --- | --- |
| A bad deploy (new code misbehaves) | `cd /opt/shieldsvpn && git checkout <previous commit or tag> && systemctl restart pqvpn-server pqvpn-portal`. The DB schema only adds columns, so older code still opens a newer DB. |
| Config mistake | Configs are in `/var/lib/pqvpn`; fix and `systemctl restart`. Keep a copy from the last backup. |
| Portal/DB corruption | `RESTORE=/path/shieldsvpn-<stamp>.tar.gz.gpg bash /opt/shieldsvpn/deploy/backup.sh --restore`, then restart. |
| Droplet lost entirely | New droplet → steps 1–3 → copy the latest backup, `--restore` it (brings back `portal.db` + `portal-secrets.key`), restore `ca/ca.key` from your offline copy, re-point DNS, re-issue TLS, start. Existing client profiles keep working because the CA and server name are unchanged. |
| Suspected key compromise | Follow the rotation runbook in [CREDENTIALS.md](CREDENTIALS.md) (server key, PSK, obfuscation key, or — worst case — the CA). |
| Vault key (`portal-secrets.key`) lost | Re-enter SMTP/Paddle secrets and reset 2FA per CREDENTIALS.md §F3. |

**Do not regenerate the CA** on a recovery unless it was compromised: a new CA invalidates every existing profile.

## 10. Moving to Hetzner later

Bandwidth is the reason to move (Hetzner EU includes ~20 TB vs DigitalOcean's 2–4 TB). The move is: new Debian 13
server → steps 1–3 → `--restore` the backup → restore `ca.key` → DNS → TLS → start. Same steps, different host; client
profiles keep working as long as the server name and CA stay the same.
