import type { Tone } from './format'

interface Props {
  tone: Tone
  busy: boolean
  label: string
  disabled?: boolean
  onPress: () => void
}

/**
 * The big connect button.  The ring and the glyph share a two-colour gradient that follows the state (brand violet
 * to cyan when off, emerald when connected, amber while busy, red on error); while busy a bright arc spins around
 * it, and when connected a soft glow breathes behind it (both disabled for prefers-reduced-motion).  Gradient stops
 * take their colours from CSS classes: the page's CSP allows no inline styles.
 */
export function PowerButton({ tone, busy, label, disabled, onPress }: Props) {
  return (
    <button
      type="button"
      className={`power power--${tone}${busy ? ' power--busy' : ''}`}
      aria-label={label}
      disabled={disabled}
      onClick={onPress}
    >
      <span className="power__glow" aria-hidden="true" />
      <svg viewBox="0 0 240 240" aria-hidden="true">
        <defs>
          <linearGradient id="power-grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" className="power__stop-a" />
            <stop offset="1" className="power__stop-b" />
          </linearGradient>
          <radialGradient id="power-core" cx="0.5" cy="0.3" r="0.75">
            <stop offset="0" className="power__core-a" />
            <stop offset="1" className="power__core-b" />
          </radialGradient>
        </defs>
        <circle className="power__track" cx="120" cy="120" r="104" />
        <circle className="power__ring" cx="120" cy="120" r="104" />
        <circle className="power__spinner" cx="120" cy="120" r="104" />
        <circle className="power__core" cx="120" cy="120" r="88" />
        <circle className="power__rim" cx="120" cy="120" r="87" />
        <path className="power__glyph" d="M137 94.6 A34 34 0 1 1 103 94.6" />
        <path className="power__glyph" d="M120 80 V116" />
      </svg>
    </button>
  )
}
