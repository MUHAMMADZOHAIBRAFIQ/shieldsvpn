# Publishing ShieldsVPN on Google Play

Everything needed to publish the Android app with a **personal** Google Play developer account. The other files in
this folder hold the text to paste into Play Console:

| File | Play Console section |
| --- | --- |
| [STORE_LISTING.md](STORE_LISTING.md) | Grow → Store presence → Main store listing |
| [APP_CONTENT.md](APP_CONTENT.md) | Policy → App content (privacy policy, ads, app access, content rating, target audience, VPN and foreground-service declarations, advertising ID, account deletion) |
| [DATA_SAFETY.md](DATA_SAFETY.md) | Policy → App content → Data safety |
| `graphics/` | App icon and feature graphic (made by `tools/play_graphics.py`); screenshots are taken from the app |

Facts in these files were checked against Google's documentation on 2026-10-30. Play's rules change; when Play Console
asks something different, Play Console wins.

## The timeline (personal account)

Google requires personal developer accounts created after 13 November 2023 to run a **closed test with at least
12 testers who stay opted in for 14 days in a row** before the app can be published to everyone. Organization accounts
(registered with a D-U-N-S number) are exempt. A public release one week after buying the account is therefore not
possible; plan for about three weeks:

| When | What |
| --- | --- |
| Days 1–2 | Server ready (below), signed bundle built, app created in Play Console, listing and App content filled in, bundle uploaded to **Internal testing** to check it installs and buys. |
| Day 2 | Same bundle to **Closed testing**; invite at least 12 testers (an email list or a Google Group) and send them the opt-in link. Every tester must opt in, install the app and keep it for 14 days. Google checks that the app was really used: ask testers to connect a few times. |
| Day 16+ | Dashboard → **Apply for production**. Answer the questions about the test (what testers did, what you changed). |
| Review | Google's review, often a few days, sometimes longer. VPN apps get a closer look (VpnService declaration). |
| Then | Production release, ideally as a staged rollout (for example 20 % first). |

## 1. Server, before anything is uploaded

The Play build registers phones with the portal on first start; it never asks for a profile file. So the portal and
the VPN server must be public, correct and switched on:

- [ ] **Portal on HTTPS with a real certificate and a domain** (for example Let's Encrypt). A playit.gg address with
  a pinned self-signed certificate works technically, but a public app should not depend on it. Set `public_url`.
- [ ] **Full tunnel to the internet works.** `nat_interface` set on the server, `full_tunnel = true` for issued
  profiles, and a DNS server pushed (`[tunnel] dns` or a plan DNS). Verify from a real phone on mobile data that web
  pages load and that the public IP is the server's. *This has not been verified yet on the live server.*
- [ ] **Premium DNS without ad blocking.** Google rejects VPN apps that "manipulate ads that can impact monetization".
  In Admin → Settings → Plans & DNS choose *Quad9* or *Cloudflare Security* (malware blocking) for Premium, not
  *AdGuard*. The app's texts no longer advertise ad blocking.
- [ ] **Enough tunnel addresses.** Every installed phone gets one address. The default `/24` subnet holds 253
  devices; a public app needs a larger subnet (for example `/16`), which means new server and portal configuration.
- [ ] Admin → Settings → **Apps**: *Apps register themselves* on; *Sign-in and sign-up in the apps* on (email must be
  set up); *Android: rewarded video ads* on with *Only count an ad when Google confirms it* on (needs the public HTTPS
  address for Google's callback).
- [ ] Admin → Settings → **Google Play Billing**: package `com.shieldsvpn.vpn`, product `shieldsvpn_pro`, service-account
  key (see step 3), *Sell Pro in the Play app* on.
- [ ] A **reviewer account**: create a user with plan *Premium* and no end date, an email address and no 2FA, for
  App access (see [APP_CONTENT.md](APP_CONTENT.md)).
- [ ] Publish the website pages `public/privacy.html` and `public/delete-account.html` (Vercel) after filling in every
  `[…]` placeholder. Their URLs go into the build and into Play Console.

## 2. Build the signed bundle

Play takes an Android App Bundle (`.aab`) signed with your **upload key**; Google re-signs the app for users (Play App
Signing).

1. Make an upload key once and keep it safe (it is not the Capacitor app's keystore in `android/`):

   ```text
   keytool -genkeypair -v -keystore shieldsvpn-upload.jks -alias upload -keyalg RSA -keysize 4096 -validity 10000
   ```

2. `android-app/keystore.properties` (git-ignored): `storeFile`, `storePassword`, `keyAlias`, `keyPassword`.
3. `android-app/deploy.properties` (git-ignored):

   ```properties
   store=play
   portalUrl=https://YOUR-PORTAL-DOMAIN/
   # portalPin only for a self-signed portal certificate
   privacyPolicyUrl=https://YOUR-SITE/privacy.html
   admobAppId=ca-app-pub-XXXXXXXXXXXXXXXX~YYYYYYYYYY
   admobRewardedId=ca-app-pub-XXXXXXXXXXXXXXXX/ZZZZZZZZZZ
   admobInterstitialId=ca-app-pub-XXXXXXXXXXXXXXXX/WWWWWWWWWW
   ```

   `store=play` turns on Google Play Billing, removes the profile-file import and refuses to build without
   `portalUrl` and `privacyPolicyUrl`. Without your own AdMob IDs the app shows Google's *test* ads.
4. Raise `versionCode` in `android-app/app/build.gradle.kts` for every upload (1, 2, 3 …).
5. Build and check:

   ```text
   cd android-app
   ./gradlew testDebugUnitTest bundleRelease
   python ../tools/secret_scan.py app/build/outputs/bundle/release/app-release.aab
   ```

## 3. Play Console setup, in order

1. **Create app**: name *ShieldsVPN – Post-Quantum VPN*, default language English, App, Free, accept the
   declarations.
2. **Monetize → Products → Subscriptions**: create product `shieldsvpn_pro` with three auto-renewing base plans,
   IDs `weekly` (P1W), `monthly` (P1M) and `yearly` (P1Y), and set their prices. Activate them. (These are the
   prices people see in the Play app; the portal's Paddle prices are only for the website and Windows.)
3. **Setup → API access** (or Users and permissions): give a Google Cloud service account access with *View financial
   data* and *Manage orders and subscriptions*; create a JSON key for it and paste it in the portal's *Google Play
   Billing* card. The portal checks every purchase with this key.
4. **Setup → License testing**: add your testers' Gmail addresses so their purchases are free test purchases.
5. **Main store listing**: text from [STORE_LISTING.md](STORE_LISTING.md), icon and feature graphic from `graphics/`,
   at least 2 phone screenshots (step 4).
6. **App content**: every item in [APP_CONTENT.md](APP_CONTENT.md) and the Data safety form from
   [DATA_SAFETY.md](DATA_SAFETY.md).
7. **Testing → Internal testing**: upload the `.aab`, add yourself, install from the opt-in link, then run through
   the test list (step 5). Then **Closed testing** with the 12+ testers.

## 4. Screenshots

At least 2, up to 8, phone screenshots (PNG or JPEG, 9:16, each side between 320 and 3840 px). Take them from the
real app on a phone or the emulator, signed in to a test account, for example: disconnected (one-tap power button),
connected (timer and traffic), the ☰ menu with *Sign up for Pro*, the Pro plan sheet, connection details. Do not use the browser preview
(`npm run dev`): it is labelled *Demo mode*. On the emulator: `adb exec-out screencap -p > shot1.png`.

## 5. Test list before Closed and before Production

- [ ] Fresh install: one tap on the power button connects without any file or account (after one rewarded ad when
  the Free time is used up); the VPN permission dialog appears once.
- [ ] Web pages load through the VPN; the public IP is the server's; no DNS or IPv6 leak.
- [ ] Free: watch a rewarded ad, time is added (Google's callback reaches the portal), the session stops when time
  runs out.
- [ ] Sign up with email code, sign in, Go Pro → Google's purchase sheet shows the three plans with local prices,
  a license-tester purchase makes the account Pro, *Manage subscription* opens Google Play's subscription page.
- [ ] Uninstall, reinstall, sign in: Pro comes back (purchases are re-checked).
- [ ] Delete account in the app: the account is gone, the phone is Free again.
- [ ] Privacy policy link in the app opens the published page.
- [ ] Always-on VPN with "Block connections without VPN" in Android settings.
- [ ] Wi-Fi ↔ mobile data while connected.

## What was and wasn't verified (2026-10-30)

Verified: the Play build compiles with Google Play Billing Library 9.1.0 and `bundleRelease` produces an `.aab`; the
build refuses `store=play` without portal and privacy URLs; portal-side purchase checks, acknowledgement, renewals,
account binding and account deletion pass tests against a fake Google API; JVM and React tests pass.

Not verified: a real purchase through Google Play (needs your Play Console app, products and license testers); the
app on a physical phone; full-tunnel internet through the live server; Google's AdMob callback on a public address.
