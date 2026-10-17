import type { Tone } from './format'

interface Props {
  tone: Tone
  busy: boolean
  label: string
  disabled?: boolean
  onPress: () => void
}

/**
 * The big connect button.  The ring colour follows the state; while busy a bright arc spins around it,
 * and when connected a soft glow breathes behind it (both disabled for prefers-reduced-motion).
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
        <circle className="power__track" cx="120" cy="120" r="104" />
        <circle className="power__ring" cx="120" cy="120" r="104" />
        <circle className="power__spinner" cx="120" cy="120" r="104" />
        <circle className="power__core" cx="120" cy="120" r="88" />
        <path className="power__glyph" d="M137 94.6 A34 34 0 1 1 103 94.6" />
        <path className="power__glyph" d="M120 80 V116" />
      </svg>
    </button>
  )
}
