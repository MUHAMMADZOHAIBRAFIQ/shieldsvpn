/**
 * The ShieldsVPN User Agreement, shown in the app before first use (agreement.tsx) and published as
 * public/terms.html.  terms.test.ts checks that the web page carries exactly this text, so change both together,
 * and raise Terms.VERSION in the app (Terms.kt) so every user accepts the new version.
 */

export interface TermsSection {
  title: string
  paragraphs?: string[]
  bullets?: string[]
  /** Paragraphs after the list. */
  after?: string[]
}

export const TERMS_TITLE = 'ShieldsVPN User Agreement'
export const TERMS_EFFECTIVE = '31 October 2026'
export const DEVELOPER = 'Dua Software Studio'
export const CONTACT_EMAIL = 'muhammadzohaibrafiq2@gmail.com'
export const PRIVACY_URL = 'https://shieldsvpn.vercel.app/privacy.html'
export const DELETE_URL = 'https://shieldsvpn.vercel.app/delete-account.html'

/** Shown in bold at the very top, as the developer asked. */
export const TERMS_HEADLINE: string[] = [
  'The developer is not responsible, at the Judgement of Allah Almighty, for anything you do by using this VPN — ' +
    'nor morally, nor before any court of law.',
  'The developer is committed to providing you with the maximum privacy and security.',
]

export const TERMS_SECTIONS: TermsSection[] = [
  {
    title: '1. Agreement to these terms',
    paragraphs: [
      `This User Agreement ("Agreement") is a legal agreement between you and ${DEVELOPER} ("we", "us", "the ` +
        'developer") for the ShieldsVPN apps for Android and Windows, the ShieldsVPN browser extension, the ' +
        'ShieldsVPN website and account portal, and the VPN service they connect to (together, the "Service").',
      'By tapping "Agree and continue", or by using the Service, you accept this Agreement and our Privacy ' +
        'Policy. If you do not agree, do not install or use the Service.',
    ],
  },
  {
    title: '2. Who can use ShieldsVPN',
    bullets: [
      'You must be at least 18 years old, or the age of majority where you live, and able to enter into a ' +
        'binding contract.',
      'You may not use the Service where the laws that apply to you forbid it, including sanctions and ' +
        'export-control laws.',
    ],
  },
  {
    title: '3. The Service',
    bullets: [
      'ShieldsVPN creates an encrypted tunnel between your device and our VPN servers using post-quantum ' +
        'cryptography (ML-KEM and ML-DSA, with an SLH-DSA root of trust, together with classical X25519).',
      'The Free plan needs no account and gives limited VPN time, earned by watching ads. Pro removes ads and ' +
        'time limits; it needs an account and a paid subscription.',
      'We may change, improve or discontinue features, servers or plans. Where a change materially affects a ' +
        'paid plan, we will tell you in advance where we reasonably can.',
    ],
  },
  {
    title: '4. Your licence to use the apps',
    paragraphs: [
      'We grant you a personal, limited, non-exclusive, non-transferable and revocable licence to install and use ' +
        'the ShieldsVPN apps on devices you own or control, for your own non-commercial use, in line with this ' +
        'Agreement and the rules of the store you got them from.',
      'You may not copy, modify, sell, rent, sublicense or distribute the apps, remove any notices from them, or ' +
        'reverse engineer them except where the law expressly allows it.',
    ],
  },
  {
    title: '5. Acceptable use',
    paragraphs: ['You must not use the Service to:'],
    bullets: [
      'break any law or regulation, or help anyone else to do so;',
      'access, store or share material that exploits or harms children, or that promotes terrorism or violence;',
      "infringe anyone's copyright, trademarks, privacy or other rights;",
      'send spam, phishing or malware, or attack, scan, probe or disrupt any network, system or service, ' +
        'including ours;',
      "commit fraud, impersonate anyone, or gain unauthorised access to any account, system or data;",
      'harass, threaten or abuse anyone;',
      'get around the limits of the Service (for example free time, ad or device limits), resell or share your ' +
        'access, or run automated use that puts an unreasonable load on our servers.',
    ],
    after: [
      'We may suspend or end access, without notice where necessary, to stop a breach of these rules, to protect ' +
        'the Service and other users, or to comply with the law.',
    ],
  },
  {
    title: '6. Your responsibility',
    bullets: [
      'You alone are responsible for what you do online while using the Service, and for obeying the laws of the ' +
        'country you are in, including any laws on the use of VPNs. Some countries restrict or forbid VPNs.',
      'A VPN protects the connection between your device and our server. It does not make you anonymous, protect ' +
        'you from malware or phishing, or make anything legal that is otherwise illegal.',
      'Keep your device, password and two-factor codes safe. You are responsible for activity under your account.',
    ],
  },
  {
    title: '7. Privacy',
    paragraphs: [
      `Our Privacy Policy (${PRIVACY_URL}) explains what we process and why. In short: we do not log the websites ` +
        'you visit, the content of your traffic or your DNS queries.',
      "To run the Service we keep only what it needs, such as your device's registration and, for Pro, your " +
        'account and purchase records. We disclose information only where the law requires it, and we cannot ' +
        'hand over traffic logs that we do not keep.',
    ],
  },
  {
    title: '8. Free plan and ads',
    paragraphs: [
      'The Free plan is supported by ads from Google AdMob. Watching a rewarded ad adds free VPN time; the amount ' +
        'of time and the daily limits may change. Ads are provided by third parties under their own terms.',
    ],
  },
  {
    title: '9. Pro subscriptions',
    bullets: [
      'Pro is a subscription billed weekly, monthly or yearly, at the price shown before you buy. Purchases in ' +
        'the Google Play app are processed by Google Play; purchases on the website or in the Windows app by ' +
        'Paddle.com, our reseller and merchant of record.',
      'Subscriptions renew automatically until you cancel. You can cancel at any time in Google Play (Payments & ' +
        'subscriptions) or through Manage subscription; Pro stays active until the end of the period you paid for.',
      'Refunds follow the policies of Google Play or Paddle and the law that applies to you. Deleting your account ' +
        'does not cancel a subscription.',
      'If a price changes, we will tell you before the new price applies to your subscription.',
    ],
  },
  {
    title: '10. Availability',
    paragraphs: [
      'We work hard to keep ShieldsVPN available and fast, but we do not promise that it will be uninterrupted, ' +
        'error-free, or available in every country or on every network. Speed depends on many things outside our ' +
        'control.',
    ],
  },
  {
    title: '11. Third-party services',
    paragraphs: [
      'The Service works with services run by others, such as Google Play, Google AdMob, Paddle and DNS ' +
        'resolvers. Their own terms and privacy policies apply to them, and we are not responsible for them.',
    ],
  },
  {
    title: '12. Intellectual property',
    paragraphs: [
      `ShieldsVPN, its apps, logo and content belong to ${DEVELOPER} or its licensors. This Agreement gives you ` +
        'no rights in them other than the licence in section 4.',
    ],
  },
  {
    title: '13. Disclaimer of warranties',
    paragraphs: [
      'To the maximum extent permitted by law, the Service is provided "as is" and "as available", without ' +
        'warranties of any kind, express or implied, including warranties of merchantability, fitness for a ' +
        'particular purpose, non-infringement, or that the Service will be secure or free of errors. No method ' +
        'of transmission or storage is completely secure.',
      'Nothing in this Agreement takes away rights you have as a consumer that the law does not allow to be ' +
        'excluded.',
    ],
  },
  {
    title: '14. No liability',
    bullets: [
      `The developer provides no liability. To the maximum extent permitted by law, ${DEVELOPER} is not liable ` +
        'for any damages or losses of any kind, whether direct, indirect, incidental, special, consequential or ' +
        'punitive, including any loss of profits, data or goodwill, arising from your use of, or inability to use, ' +
        'the Service.',
      'We are not responsible for what you do while using the Service, or for the content you access through it.',
    ],
    after: [
      'Where a law does not allow liability to be excluded completely, our liability is limited to the smallest ' +
        'amount that law permits.',
    ],
  },
  {
    title: '15. Indemnity',
    paragraphs: [
      `You agree to indemnify and hold harmless ${DEVELOPER} against claims, losses and costs (including ` +
        'reasonable legal fees) that arise from your misuse of the Service or your breach of this Agreement or ' +
        'of the law.',
    ],
  },
  {
    title: '16. Suspension and termination',
    paragraphs: [
      `You may stop using the Service at any time, and delete your account in the app or as described at ${DELETE_URL}.`,
      'We may suspend or end your access if you breach this Agreement, if the law requires it, or to protect the ' +
        'Service or others. Sections 6 and 12 to 18 continue to apply after the Agreement ends.',
    ],
  },
  {
    title: '17. Changes to this Agreement',
    paragraphs: [
      'We may update this Agreement. We will publish the new version in the app and on our website; for ' +
        'important changes the app asks you to accept the new version before you continue. If you do not accept ' +
        'it, stop using the Service.',
    ],
  },
  {
    title: '18. Governing law and disputes',
    paragraphs: [
      'This Agreement is governed by the laws of the Islamic Republic of Pakistan and by applicable international ' +
        'law, including the international conventions to which Pakistan is a party. The courts of Pakistan have ' +
        'jurisdiction, except where the consumer laws of your country give you the right to bring a claim where ' +
        'you live.',
      'Before starting any claim, please contact us first so that we can try to resolve the matter informally.',
    ],
  },
  {
    title: '19. General',
    bullets: [
      'This Agreement and the Privacy Policy are the entire agreement between you and us about the Service.',
      'If any part of this Agreement cannot be enforced, the rest remains in effect. If we do not enforce a right, ' +
        'we have not waived it.',
      'We may transfer this Agreement to a successor of our business; you may not transfer it without our consent.',
      'The terms of the store you downloaded the app from also apply. This Agreement is written in English; any ' +
        'translation is for convenience only.',
    ],
  },
  {
    title: '20. Contact',
    paragraphs: [`${DEVELOPER} — ${CONTACT_EMAIL}`],
  },
]

/** Every sentence of the Agreement in reading order (the web page must contain each of them). */
export function termsText(): string[] {
  return [
    TERMS_TITLE,
    ...TERMS_HEADLINE,
    ...TERMS_SECTIONS.flatMap((s) => [s.title, ...(s.paragraphs ?? []), ...(s.bullets ?? []), ...(s.after ?? [])]),
  ]
}
