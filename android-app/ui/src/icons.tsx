/** Inline SVG icons (no icon font or network fetch: the CSP allows nothing but our own bundle). */
import type { ReactNode } from 'react'

const Svg = ({ children, size = 20 }: { children: ReactNode; size?: number }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={1.8}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    {children}
  </svg>
)

/** The ShieldsVPN shield-and-lock logo (geometry from pqvpn/logo.py). */
export const ShieldLogo = ({ size = 32 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
    <defs>
      <linearGradient id="logo-g" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor="#6366f1" />
        <stop offset="1" stopColor="#0891b2" />
      </linearGradient>
    </defs>
    <path d="M50 4 L87 16 C87 52 74 79 50 96 C26 79 13 52 13 16 Z" fill="url(#logo-g)" />
    <path d="M35 52 V44 A15 15 0 0 1 65 44 V52 H59 V44 A9 9 0 0 0 41 44 V52 Z" fill="#fff" />
    <rect x="31" y="48" width="38" height="28" rx="4" fill="#fff" />
    <circle cx="50" cy="59" r="4.5" fill="url(#logo-g)" />
    <path d="M47.6 61 H52.4 L53.6 70 H46.4 Z" fill="url(#logo-g)" />
  </svg>
)

export const IconDown = () => (
  <Svg><path d="M12 4v14" /><path d="m6 12 6 6 6-6" /></Svg>
)
export const IconUp = () => (
  <Svg><path d="M12 20V6" /><path d="m6 12 6-6 6 6" /></Svg>
)
export const IconServer = () => (
  <Svg><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></Svg>
)
export const IconPin = () => (
  <Svg><path d="M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11Z" /><circle cx="12" cy="10" r="2.5" /></Svg>
)
export const IconLock = () => (
  <Svg><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></Svg>
)
export const IconId = () => (
  <Svg><rect x="3" y="5" width="18" height="14" rx="2" /><circle cx="9" cy="12" r="2.5" /><path d="M14 10h4M14 14h3" /></Svg>
)
export const IconRoute = () => (
  <Svg><circle cx="6" cy="18" r="2.5" /><circle cx="18" cy="6" r="2.5" /><path d="M8.5 18H15a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h6.5" /></Svg>
)
export const IconGlobe = () => (
  <Svg><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></Svg>
)
export const IconClock = () => (
  <Svg size={16}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></Svg>
)
export const IconImport = () => (
  <Svg><path d="M12 3v12" /><path d="m7 10 5 5 5-5" /><path d="M5 21h14" /></Svg>
)
export const IconTrash = () => (
  <Svg><path d="M4 7h16M10 11v6M14 11v6" /><path d="M6 7l1 13h10l1-13M9 7V4h6v3" /></Svg>
)
export const IconExternal = () => (
  <Svg><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></Svg>
)
export const IconAlert = () => (
  <Svg><path d="M12 3 2 20h20Z" /><path d="M12 10v4M12 17h.01" /></Svg>
)
export const IconCheck = () => (
  <Svg><circle cx="12" cy="12" r="9" /><path d="m8 12 3 3 5-6" /></Svg>
)
export const IconMenu = () => (
  <Svg size={22}><path d="M4 7h16M4 12h16M4 17h10" /></Svg>
)
export const IconClose = () => (
  <Svg><path d="M6 6l12 12M18 6 6 18" /></Svg>
)
export const IconCrown = () => (
  <Svg><path d="M3 8l4.5 4L12 5l4.5 7L21 8l-2 11H5Z" /><path d="M5 19h14" /></Svg>
)
export const IconUser = () => (
  <Svg><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></Svg>
)
export const IconLogout = () => (
  <Svg><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" /><path d="M10 16l-4-4 4-4M6 12h10" /></Svg>
)
export const IconShieldCheck = () => (
  <Svg><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6Z" /><path d="m8.8 12 2.2 2.2 4.2-4.4" /></Svg>
)
export const IconDoc = () => (
  <Svg><path d="M7 3h7l5 5v13H7Z" /><path d="M14 3v5h5M10 13h6M10 17h6" /></Svg>
)
export const IconPlay = () => (
  <Svg size={16}><circle cx="12" cy="12" r="9" /><path d="M10 8.5v7l6-3.5Z" /></Svg>
)
export const IconTick = () => (
  <Svg size={18}><path d="m5 12.5 4.5 4.5L19 7.5" /></Svg>
)
