# ShieldsVPN privacy policy (draft)

> **Draft for the owner, not legal advice.** Fill in the bracketed parts, have it reviewed (especially for the
> EU/UK GDPR, Pakistan's data-protection rules and Google Play's User Data policy), and keep it in step with the
> code. It describes what the software stores as of 2026-10-22; if the settings or the code change, update it.

Last updated: [DATE]

ShieldsVPN is operated by [OWNER / COMPANY NAME], [ADDRESS] ("we"). Contact: [CONTACT EMAIL].

## What we never collect

We do not log the websites you visit, the content of your traffic or your DNS queries. The VPN server forwards
encrypted packets and keeps no record of where they go.

## What we store, and why

| Data | When | Why | How long |
| --- | --- | --- | --- |
| A random device name, a tunnel address, a device key's public part and certificate | when the app sets itself up | to let your device connect | until 30 days after the device was last used (Free, no account), or until you delete the device or account |
| The IP address that set the device up | at setup | to limit abuse (devices per network per day) | as above |
| Free-time balance and ad-reward records (time, ad network transaction id) | when you watch an ad | to grant free time and enforce daily limits | reward records 7 days |
| Live connection data: your public IP and port, connection start time, bytes sent and received | while connected | to run the connection and show the administrator who is online | overwritten every few seconds; not kept after you disconnect |
| Last time the device connected | every minute while connected | to free unused devices | as the device |
| Account (Pro): email, password hash, optional 2FA secret, plan and its end date | when you create an account | sign-in, Pro, password recovery | until you ask us to delete the account |
| Security log: sign-ins, failed sign-ins, password resets, plan changes, with IP address | when they happen | to protect accounts and investigate abuse | [RETENTION PERIOD — not automatically deleted today] |

## Third parties

- **Google AdMob (Free plan in the Android app).** To show ads, Google's Mobile Ads SDK collects device information,
  including the advertising ID, and may use it for personalised ads where you consent. Where the law requires it,
  you are asked for consent first. See Google's policy: <https://policies.google.com/technologies/partner-sites>.
- **Paddle (Pro payments).** Paddle.com is our reseller and merchant of record. It processes your card and billing
  details; we never see your card number. We receive a customer and subscription ID, the amount and the status.
  See Paddle's privacy policy: <https://www.paddle.com/legal/privacy>.
- **Email.** Verification and password-reset codes are sent through [EMAIL PROVIDER, e.g. Gmail SMTP].
- **[Optional] Firebase.** If enabled by us, a copy of account names, emails, plans, connection status and the
  security log is kept in Google Firebase. Passwords, 2FA secrets and codes are never copied.

## Your choices and rights

- Use the Free plan without an account. Removing the app's profile deletes its keys from your phone.
- Ask us to delete your account and devices, or for a copy of your data: [CONTACT EMAIL].
- Change ad consent in the app's ad consent form, or reset your advertising ID in Android settings.
- Cancel Pro at any time through *Manage subscription* (Paddle).

## Security

Connections use post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA, together with classical X25519). Passwords are
stored only as scrypt hashes. On your phone, the device key is protected by the Android Keystore; on Windows by
DPAPI. No system is perfectly secure; tell us about problems at [CONTACT EMAIL].

## Children

ShieldsVPN is not directed at children under [13 / 16 depending on country].

## Changes

We will post changes here and update the date above.
