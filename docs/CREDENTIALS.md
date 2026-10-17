# Credentials: inventory, handling and rotation

This file lists **types** of secret material and where they live. It never contains secret values. Do not paste
keys, PSKs, passwords or tokens into issues, chats, screenshots or this file.

## What counts as a secret here

| Material | Typical file | Who holds it | Impact if leaked |
| --- | --- | --- | --- |
| CA private key (SLH-DSA) | `ca.key` | Offline / portal host only | Attacker can mint server and client certificates. Rotation means a new CA and reissuing everything. |
| Server private key (ML-DSA) | `server.key` | VPN server | Server impersonation. |
| Client private key (ML-DSA) | `client.key`, inside the profile ZIP | One device | Connecting as that user until the serial is superseded or revoked. |
| Pre-shared key (32 bytes, base64) | `psk.key` / `psk_file` | Server and all clients | Removes the PSK layer only. The certificates still authenticate. |
| Portal database | `portal.db` (+ `-wal`, `-shm`) | Portal host | Password hashes, TOTP seeds, e-mail addresses, sealed vault entries. |
| Portal vault key | `portal-secrets.key` | Portal host | Decrypts the sealed secrets in the database. |
| Key passphrase files | `*_passphrase_file` | Next to the key | Unlocks the matching encrypted key. |
| Android release keystore and properties | `*.jks`, `keystore.properties` | Release machine | App-update impersonation on users' phones. |
| Firebase or other service-account JSON | `*firebase*.json` | Portal host | Access to that cloud project. |

Configuration files (`server.toml`, `client.toml`, `portal.toml`) refer to secrets **by path**. Keep it that way:
never inline a secret into a config file. Templates with placeholders are in [deploy/examples/](../deploy/examples/).

## Guard rails in this repository

* `.gitignore` excludes all of the above: `*.key`, `*.pem` (except `docs/**/*.pem`), `vpn-pki*/`, `vpn-profiles/`,
  `.local-pqvpn/`, profile ZIPs, `*.db*`, `portal-secrets.key`, `*.jks`, `*.keystore`, `keystore.properties`,
  `.env*` and Firebase keys.
* `python tools/secret_scan.py` scans everything `git add -A` would stage. It also accepts files, directories, an
  APK or a ZIP (including Chaquopy's nested `.imy` archives). It reports **path and type only**, never the
  matched bytes, and exits 1 on a finding. `tests/test_secret_scan.py` runs it on the repository as part of the
  test suite.
* Before publishing an APK, run `python tools/secret_scan.py android-app/app/build/outputs/apk/<variant>/<apk>`.

## Inventory of this working copy (2026-10-17)

Every item below is git-ignored. None of them is tracked, and none was found in `origin` (which has only `main`).

| Location | Contents (types only) | Status |
| --- | --- | --- |
| `vpn-profiles/pqvpn-sohaib/` | Client private key for user `sohaib`, the deployment's shared PSK, certificates | **Live deployment.** Rotate if this folder or its ZIP ever left the machine (see below). |
| `.local-pqvpn/` | Local test portal: CA key, server key, PSK, vault key, `portal.db` | Local testing only. |
| `vpn-pki-local/` | `pqvpn quickstart` PKI: CA, server and client keys | Local testing only. |
| `android/` | Release keystore and its password properties | Required before any Play/public release. |

**Local-only git refs.** Some test-portal files (`.local-pqvpn/portal.db` and certificates/configs) exist in
commits on **local** refs `refs/agents/...` and `refs/codex/...`. These refs were never pushed. Do not push them.
To remove them from the local object store, the owner can run the following once they have confirmed that
nothing on those refs is needed:

```sh
git for-each-ref --format='%(refname)' refs/agents refs/codex   # review first
git update-ref -d <ref>                                           # per ref, owner's decision
git reflog expire --expire=now --all && git gc --prune=now
```

This was **not** done automatically. It deletes history, so it needs the owner's explicit decision.

## Rotation runbook

Rotate when a device is lost, when a profile ZIP or key file was shared or uploaded anywhere (chat, e-mail, cloud
drive, screenshot, public repository), or when someone who had access leaves.

### A. One user's client key (most common)

1. In the portal, have the user download a **new profile**, or do it as an admin. The portal records the new
   certificate serial as the account's active profile. The VPN server checks every connecting serial against the
   portal database ([pqvpn/portal/access.py](../pqvpn/portal/access.py)), so the **old serial stops working within
   one status interval (about 2 s)**. No CRL distribution is needed.
2. Without a portal (static config), add the old serial to `[security] revoked_serials` in `server.toml` and
   restart the server. `pqvpn show client.crt` prints the serial.
3. Delete the old profile ZIP and key everywhere it was copied. On Android, remove the profile in the app, which
   deletes the Keystore-sealed secrets.

### B. The shared PSK

The PSK is shared by the server and every client, so rotating it requires reissuing every profile.

1. `pqvpn genpsk > psk.key.new`, and give it mode 0600 on the server.
2. Point `[crypto] psk_file` (server) and the portal's `[vpn] psk_file` at the new file.
3. Restart the server and portal. From then on, clients still holding the old PSK fail the handshake, by design.
4. Every user downloads a new profile, which contains the new PSK.

To avoid a hard cut-over, schedule it and announce it. pqvpn deliberately has no "accept two PSKs" mode.

### C. Server key

Issue a new server certificate from the CA (`pqvpn issue --role server ...`), replace `server.key`/`server.crt`
and restart. Clients are unaffected, because they trust the CA and the server name, not the key.

### D. CA key (compromise or loss)

1. `pqvpn ca-init` creates a new CA.
2. Issue a new server certificate.
3. Reissue every client profile.
4. Ship the new CA certificate in those profiles and remove the old one from `ca` lists.

Revoking a live CA cuts off every user at once, so plan it as an outage. It needs the operator's decision.

### E. Android release keystore

Losing or leaking the keystore cannot be fixed by rotation on the Play Store unless Play App Signing is used.
Before the first public release:

1. Create a fresh keystore that has never been on a shared machine.
2. Keep it offline and back it up.
3. Enrol in Play App Signing.

## If a secret was pushed to a remote

1. **Rotate first**, using the steps above. History rewriting does not un-leak a secret.
2. Then, with the repository owner's authorization, remove it from history (`git filter-repo --path <file>
   --invert-paths`) and force-push. Every clone and fork still holds the old objects, so step 1 is what actually
   protects you.
