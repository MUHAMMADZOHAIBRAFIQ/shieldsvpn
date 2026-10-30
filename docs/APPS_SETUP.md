# Free with ads, sign-in and Pro: setup guide

This guide turns on the features added on 2026-10-22 and tests them through playit.gg before you buy a domain.
The design is in [SPEC.md §16](SPEC.md#16-app-devices-free-with-ads-sign-in-and-pro). Security notes are in
[SECURITY.md](SECURITY.md#apps-free-with-ads-sign-in-and-pro).

## What users get

| | Free | Pro |
| --- | --- | --- |
| Sign-up | none: the app sets itself up on first start | email + password, verified by an emailed code |
| Time | 30 minutes per watched ad (you choose the number), up to 16 ads a day | unlimited |
| Ads | video ad for time (Android), ad web page (Windows), an ad after connecting (Android) | none |
| Extras | | ad- and malware-blocking DNS, up to 5 devices |
| Payment | | card, through Paddle's checkout; you set the price in Paddle |

The VPN server enforces free time itself. An app that skips the ads still cannot connect.

## 0. Before you start

1. **Lock down the admin account.** Change the admin password and keep `require_2fa_for_admins = true` in
   `portal.toml`. The portal will be reachable from the internet.
2. **Update the server and the portal** to this version and restart both: the VPN server must load the new access
   rules. A restart drops connected users for a few seconds.
3. **playit.gg TCP tunnel** to the portal port (for example local `127.0.0.1:8800`). Your existing UDP tunnel stays
   for the VPN itself. Check in your playit account whether TCP tunnels need the paid plan.
4. **Paddle sandbox account** (free): <https://sandbox-vendors.paddle.com/signup>. At the same time, **ask Paddle
   support** whether they accept (a) a VPN subscription and (b) a seller based in Pakistan. If either answer is no,
   tell me before launch: another provider can be added behind the same checkout code.
5. **AdMob account** (optional while testing): the app uses Google's public **test** ad IDs until you put your own in.
6. **Address space.** A `/24` VPN subnet holds about 250 devices, and every phone that installs the app takes one
   address (unused anonymous devices are freed after 30 days). Before a public launch, widen the subnet (for example
   to `/16`). That needs a new *server* certificate from the same CA; user profiles stay valid. Ask me to do it with
   you.

## 1. Give the portal HTTPS and get its pin

The portal refuses to start without HTTPS once `public_url` names a domain or a public address (a tunnel would
otherwise carry passwords in clear text). A self-signed certificate is fine for testing because the apps *pin* it.
They accept exactly this certificate and nothing else.

Known limit while testing through playit: every request reaches the portal from 127.0.0.1, so the per-network
limits (sign-in attempts, 20 new devices per day) are shared by all users. Fine for you and a few testers; fix it
before a public launch (see [SECURITY.md](SECURITY.md#apps-free-with-ads-sign-in-and-pro), "Open issue").

```sh
cd /var/lib/pqvpn
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
  -keyout portal-tls.key -out portal-tls.crt -subj "/CN=shieldsvpn-portal"
chmod 600 portal-tls.key
```

In `portal.toml` (`[portal]` section):

```toml
tls_certificate = "portal-tls.crt"
tls_private_key = "portal-tls.key"
public_url = "https://YOUR-PLAYIT-HOST:PORT/"      # the playit TCP address
allowed_hosts = ["YOUR-PLAYIT-HOST"]
```

Restart the portal. Its log prints a line like:

```text
TLS certificate pin for the apps (portalPin in android-app/deploy.properties): 3f9a...  (64 hex digits)
```

Keep that value: it goes into the Android build and the Windows command. Create a new certificate and the pin
changes, so every app build must be updated.

## 2. Switch the features on

Admin console (`/admin`) → **Settings** → **Apps: Free with ads & Pro**:

| Switch | For testing through playit | For launch |
| --- | --- | --- |
| Apps register themselves | on | on |
| Sign-in and sign-up in the apps | on (needs email set up) | on |
| Android: rewarded video ads | on | on |
| Only count an ad when Google confirms it | **off** (test mode: Google cannot call a self-signed portal) | **on** |
| Windows: ad on a web page | on | on, once you have an ad network |
| Show a test ad on that page | on | off |

The numbers (minutes per ad, ads per day, devices per account) can be changed any time.

**App devices** (from the dashboard) lists every registered phone and PC. Disable or delete a device there.

## 3. Payments (Paddle sandbox)

In the Paddle **sandbox** dashboard:

1. **Catalog → Products:** create a product "ShieldsVPN Pro" (no prices needed). Copy its product ID (`pro_...`).
2. **Developer tools → Authentication:** create an **API key** (with permission to write prices and transactions)
   and a **client-side token** (`test_...`).
3. **Checkout → Checkout settings:** set the *default payment link* to `https://YOUR-PLAYIT-HOST:PORT/pay`.

In the admin console → **Settings → Payments (Paddle)**: tick *Sell Pro*, choose *Sandbox*, paste the product ID,
the API key and the client-side token, choose the currency, and type the **weekly, monthly and yearly** amounts
(for example `1.99`, `4.99`, `39.99`; leave one empty to not sell that period). On save the portal creates those
prices in Paddle for you. To change a price later, change the amount and save: a new price is created and the old one
archived, and people who already subscribe keep paying what they signed up for. Buyers pick the period in the apps
and on the web Upgrade page. Webhooks are optional until you have a domain: Pro is confirmed by asking Paddle's API
directly.

Pay with one of Paddle's sandbox test cards (Paddle documents them under "test cards"). No real money moves in
the sandbox.

## 4. Android app

Create `android-app/deploy.properties`. The file is git-ignored; never commit it.

```properties
portalUrl=https://YOUR-PLAYIT-HOST:PORT/
portalPin=THE-64-HEX-DIGIT-PIN-FROM-STEP-1
# Later, your own AdMob IDs (without these lines Google's test IDs are used):
# admobAppId=ca-app-pub-XXXXXXXXXXXXXXXX~YYYYYYYYYY
# admobRewardedId=ca-app-pub-XXXXXXXXXXXXXXXX/ZZZZZZZZZZ
# admobInterstitialId=ca-app-pub-XXXXXXXXXXXXXXXX/WWWWWWWWWW
```

Build and install as usual (`cd android-app && ./gradlew assembleRelease`). On first start the app sets itself up
and shows the **Free plan** card. A build without `deploy.properties` behaves like before: profiles are imported
from the portal's ZIP.

## 5. Windows app

```powershell
python -m pqvpn app --portal https://YOUR-PLAYIT-HOST:PORT/ --pin THE-64-HEX-DIGIT-PIN --install-shortcut
python -m pqvpn app --portal https://YOUR-PLAYIT-HOST:PORT/ --pin THE-64-HEX-DIGIT-PIN
```

The first command registers the PC and creates the Desktop/Start-menu shortcut. Afterwards `python -m pqvpn app`
(or the shortcut) is enough. *Get free time* opens the ad page in the browser; *Go Pro* opens the checkout.

## 6. Test checklist

1. Android: install → the app registers itself; Free plan, `00:00:00`, "A short ad gives you 30 free minutes".
2. Tap Connect once → a rewarded ad plays → 30 minutes → the app connects by itself (no second ad for that
   connection). A later Connect with time left shows an ad after connecting.
3. Admin → App devices: the phone is listed as Free with minutes left.
4. Let the time run out (or set *Free minutes per ad* to 1 for the test) → the app disconnects with a message.
5. ☰ menu → *Sign up for Pro* → create an account → enter the emailed code → the plan sheet opens.
6. Go Pro → pay in the sandbox → back in the app the card shows **ShieldsVPN Pro**; Connect works with no ads.
7. Windows: *Get free time* → wait on the ad page → press its button → the window shows the minutes.
8. Admin → disable the device → its VPN session ends within seconds.

## 7. Before a public launch

- Buy a domain and get a real certificate (Let's Encrypt, or Cloudflare Tunnel), then remove `portalPin` from the
  build (normal certificate checks take over).
- Turn **Only count an ad when Google confirms it** back on and paste the AdMob callback URL shown on the settings
  page into the AdMob console.
- Your own AdMob app and ad unit IDs in `deploy.properties`.
- Paddle **live** account, approved domain, live keys; a webhook destination
  `https://YOUR-DOMAIN/api/v1/paddle/webhook`.
- A published privacy policy (draft: [PRIVACY_POLICY_DRAFT.md](PRIVACY_POLICY_DRAFT.md)): required for ads and for
  Google Play.
- **Google Play:** Play's payments policy will probably require Google Play Billing for Pro bought *inside* a
  Play-distributed app. Check this before publishing there. APKs you distribute yourself are not affected.
- Refunds and chargebacks are not applied automatically yet: set the user's plan back in Admin → Users.

## What was and wasn't verified (2026-10-22)

Verified:

- Python: 137 tests on Windows and in WSL. One run in five on Windows had one intermittent error that did not
  repeat; its output was not captured.
- React: 25 Vitest tests. Android JVM: 16 tests. Debug APK built.
- Headless Chrome against a throwaway portal: admin settings and devices pages, the web ad page (locked button,
  time granted), the pay page loading Paddle.js with no CSP violations.
- API 36 emulator against a local portal and a real VPN server:
  - registration and the "no free time" refusal;
  - a real Google **test** rewarded video, then 30 minutes;
  - VPN consent, connect, and traffic through the tunnel;
  - automatic stop when the time ran out, with the server dropping the session;
  - in-app sign-up with the emailed code;
  - Go Pro opening the checkout link in Chrome; Pro switching on after a *simulated* payment;
  - Pro connecting with no free time and no ads, with AdGuard DNS.
- Windows window and sign-in dialog, rendered against a throwaway portal (screenshots).
- 2026-10-30, one-tap app (API 36 emulator, local portal + real VPN server, AdMob test mode): a fresh install
  registered itself on opening; one tap on the power button played Google's **test** rewarded video, the portal
  granted 30 minutes, the app connected by itself after the notification and VPN permission dialogs, with no
  interstitial for that connection; pings through the tunnel answered. The ☰ menu opened, *Sign up for Pro*
  opened the sign-up sheet, and Android's Back closed the menu and sheets without leaving the app. React: 38 Vitest
  tests; Android JVM: 21 tests.
- 2026-10-30, same flow over the internet: a signed release APK with `portalUrl` = a Cloudflare quick tunnel to the
  Kali portal (normal certificate checks, no pin) registered on the emulator, played the test ad, and connected to
  the Kali VPN server through playit.gg in full-tunnel mode; pings to the server (10.8.0.1) and to 1.1.1.1 went
  through the tunnel. Web browsing and DNS-leak checks were not run.
- 2026-10-31, User Agreement (API 36 emulator): a fresh install shows it before anything else; Decline closes the
  app and it asks again on the next start; after Agree it does not return on later starts, and after uninstall and
  reinstall it is shown again. The ☰ menu's *User agreement* opens it read-only.

Not verified:

- **A real Paddle sandbox payment.** Payments were simulated by a fake Paddle API. The real checkout overlay
  needs your sandbox keys.
- Weekly / monthly / yearly prices (added 2026-10-30): creating and archiving prices was tested against the fake
  Paddle API only, not Paddle's real `/prices` endpoint; the plan choice in the apps and on the web was tested with
  unit tests, not on the emulator or in a browser. The Android plan sheet (weekly / monthly / yearly) was checked in
  the browser preview only; on the emulator the test portal sold a single plan.
- The one-tap flow on a real phone, and through a portal on the internet: the emulator test used a local portal.
- AdMob server-side verification with Google's real callback. It needs a public HTTPS address; signed callbacks
  were tested with a local key.
- The interstitial after connecting actually showing. On the emulator it was requested but could not load: the
  test VPN server pushed a DNS address it does not answer. A real server's DNS works.
- Anything through playit.gg; real phones; the Windows window driven end to end (sign-in, ad page and connect with
  UAC); the tray's new menu item; full-tunnel internet.
- Paddle's acceptance of a VPN product and a Pakistani seller.
