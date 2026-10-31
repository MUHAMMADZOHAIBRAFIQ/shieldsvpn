# Data safety form

Answers for Play Console → App content → Data safety, for the Play Store build. "Collected" means the data leaves the
phone (to our portal or to an SDK's company). Data handled only on the phone is not declared. Google's guidance for
the SDKs we use: [Mobile Ads SDK](https://developers.google.com/admob/android/privacy/play-data-disclosure) and
[Google Play Billing](https://developer.android.com/google/play/billing/data-safety). Check those pages when you fill
in the form; they describe what the SDKs collect in their current versions.

## Overview questions

| Question | Answer |
| --- | --- |
| Does the app collect or share any of the required user data types? | Yes |
| Is all collected data encrypted in transit? | Yes (HTTPS to the portal, the post-quantum VPN protocol to the server, Google's SDKs use TLS) |
| Do you provide a way for users to request that their data is deleted? | Yes: in the app (Delete account) and at `https://shieldsvpn.vercel.app/delete-account.html` |

## Data types

| Data type | Collected / shared | Optional? | Purposes | Where it comes from |
| --- | --- | --- | --- | --- |
| **Personal info → Email address** | Collected, not shared | Optional (only for an account / Pro) | Account management, app functionality | Sign-up and sign-in in the app |
| **Financial info → Purchase history** | Collected, not shared | Optional | App functionality (turning Pro on) | Google Play purchase token, plan, state and end date, checked by the portal |
| **Location → Approximate location** | Collected; shared by the Mobile Ads SDK | Required | Fraud prevention, security (our portal keeps the IP address that registered a device and IPs in the security log); advertising (AdMob derives location from the IP address) | IP address |
| **Device or other IDs** | Collected; the advertising ID is shared by the Mobile Ads SDK | Required | App functionality, fraud prevention (our random device name and device token; a hash of Android's per-app ID, so a reinstalled app gets its unused free time back); advertising, analytics (AdMob's advertising ID) | App registration; Mobile Ads SDK |
| **App activity → App interactions** | Collected and shared by the Mobile Ads SDK | Required on Free | Advertising, analytics, fraud prevention | Ad views and taps |
| **App info and performance → Diagnostics** | Collected by the Mobile Ads SDK | Required on Free | Analytics, fraud prevention | SDK diagnostics |

Not collected: name, phone number, address, contacts, photos, files, messages, calendar, health, precise location,
web browsing history, the content or destinations of VPN traffic, DNS queries.

**Is the data processed ephemerally?** For live connection data (public IP and port, bytes sent and received) yes:
it is overwritten every few seconds and removed on disconnect. Declare the IP address under *Approximate location* as
above because the registration IP is kept.

## Notes for the answers

- "Shared" in Play's sense excludes service providers acting for you. Payments processed by Google Play, email sent
  through your provider and the optional Firebase copy are service-provider uses, not sharing.
- If you turn on the Firebase mirror, the account email and plan are also stored in Firebase; this is still
  "collected" (already declared), not "shared".
- If you later add analytics, crash reporting or another ad network, update this form before releasing that version.
