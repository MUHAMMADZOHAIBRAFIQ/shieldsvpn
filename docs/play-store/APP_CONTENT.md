# App content (Policy → App content)

Answers for every App content item Play Console asks a VPN app like ShieldsVPN. They describe the Play Store build
(`store=play`) as the code is on 2026-10-30. If the app or the server settings change, update the answers: a wrong
declaration is a policy violation in itself.

## Privacy policy

`https://shieldsvpn.vercel.app/privacy.html` (from `public/privacy.html`, with every `[…]` filled in). The same address is built
into the app (`privacyPolicyUrl`) and opened from the *Privacy policy* link at the bottom of the screen, as Google's
User Data policy requires.

## Ads

**Yes, the app contains ads.** Free users can watch rewarded video ads for free VPN time, and an interstitial may
show after a Free device connects (Google AdMob, with Google's consent form where the law requires it). Pro users see
no ads.

## App access

**All or some functionality is restricted.** Give the reviewers a Premium account so they can test without watching
ads:

| Field | Value |
| --- | --- |
| Name | Reviewer account (Pro) |
| Username | [REVIEWER EMAIL] (an account in the portal with plan Premium, no end date, no 2FA) |
| Password | [REVIEWER PASSWORD] |
| Instructions | Open the app and tap the round power button, then allow the VPN request. The Free plan needs no account: the first tap plays one short rewarded ad that adds 30 minutes, then connects. To test Pro, open the ☰ menu, tap "Sign in" and use the account above. |

## Content rating (IARC questionnaire)

Category: **Utility, Productivity, Communication, or Other**. Answer **No** to violence, sexuality, language,
controlled substances, gambling, and to "users can interact or exchange content". Answer **Yes** to "the app
contains ads" and to digital purchases (in-app subscriptions). Expected rating: Everyone / PEGI 3.

## Target audience and content

Target age group: **18 and over** only. The app is not designed for children, and choosing only 18+ keeps it out of
the Families policy (which restricts ads and data collection for children). Answer **No** to "could the app
unintentionally appeal to children".

## News app, COVID-19, government, financial features, health

All **No**. (Selling a subscription is not a "financial feature" in Play's sense.)

## Data safety

See [DATA_SAFETY.md](DATA_SAFETY.md).

## Advertising ID

**Yes, the app uses the advertising ID**: Google AdMob (Mobile Ads SDK) uses it for advertising and analytics.
The SDK adds the `com.google.android.gms.permission.AD_ID` permission to the app.

## VPN service (VpnService declaration)

| Question | Answer |
| --- | --- |
| Is VPN the app's core functionality? | Yes. The app creates a device-level encrypted tunnel to the ShieldsVPN server; that is its purpose. |
| Does the app collect personal or sensitive user data through VpnService? | No. The tunnel forwards encrypted packets to our server; the app does not inspect, log, collect or share the traffic. |
| Does the app redirect or manipulate traffic from other apps for monetization (for example ads)? | No. (Keep it true: the Premium DNS must not be an ad-blocking resolver; see the server checklist in [README.md](README.md).) |
| Is traffic encrypted from the device to the VPN endpoint? | Yes: hybrid ML-KEM-768 + X25519 key exchange, ML-DSA-65 authentication, ChaCha20-Poly1305 or AES-256-GCM. |
| Listing disclosure | The full description has an "About the VPN permission" paragraph (see [STORE_LISTING.md](STORE_LISTING.md)). |

## Foreground service permissions

The VPN runs as a foreground service while connected (the "connected" notification). The manifest declares
`foregroundServiceType="systemExempted|specialUse"` with special-use subtype `vpn`; `systemExempted` is the type Android
documents for apps holding VPN consent, `specialUse` is only a fallback for devices that refuse it.

- **Task:** keeps the user-started VPN tunnel running while the screen is off or another app is in front, and shows
  that the VPN is on with a Disconnect button.
- **User impact if deferred or stopped:** traffic would leave the encrypted tunnel or stop; with "Block connections
  without VPN", the phone would lose its connection.
- **Video:** Play asks for a short screen recording (a YouTube or Drive link): open the app, tap Connect, accept the
  VPN request, show the notification, switch to another app and browse, then tap Disconnect in the notification.

## Account deletion

**Yes, users can create an account in the app.**

- In the app: Your plan → **Delete account** (password, plus the authenticator code if 2FA is on). Implemented by
  `POST /api/v1/account/delete`.
- Web link for requests without the app: `https://shieldsvpn.vercel.app/delete-account.html` (from `public/delete-account.html`).
- Data deleted / kept: as listed on that page and in [DATA_SAFETY.md](DATA_SAFETY.md).

## Permissions the app requests (for reference)

| Permission | Why |
| --- | --- |
| `INTERNET`, `ACCESS_NETWORK_STATE` | the encrypted connection to the server; noticing Wi-Fi ↔ mobile changes to reconnect |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`, `FOREGROUND_SERVICE_SPECIAL_USE` | the VPN service and its notification |
| `POST_NOTIFICATIONS` | the "connected" notification (asked once, on first connect) |
| `com.android.vending.BILLING` | Google Play Billing (added by the billing library) |
| `AD_ID` and AdMob's network permissions | ads on the Free plan (added by the Mobile Ads SDK) |
| `BIND_VPN_SERVICE` (on the service) | only Android may bind the VPN service |
