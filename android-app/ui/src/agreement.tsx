import { ShieldLogo } from './icons'
import { DEVELOPER, TERMS_EFFECTIVE, TERMS_HEADLINE, TERMS_SECTIONS, TERMS_TITLE } from './terms'

/**
 * The User Agreement as a full-screen page.  "accept" mode is shown once per installation, before the app
 * registers or connects (the app keeps the acceptance in no-backup storage, so a new install asks again);
 * "read" mode is opened from the menu.  All text comes from terms.ts and is rendered as text, never as HTML.
 */
export function Agreement(props: {
  mode: 'accept' | 'read'
  onAccept?: () => void
  onDecline?: () => void
  onClose?: () => void
}) {
  return (
    <div className="agreement" role="dialog" aria-modal="true" aria-labelledby="terms-title">
      <header className="agreement__head">
        <ShieldLogo size={34} />
        <div>
          <h2 id="terms-title">{TERMS_TITLE}</h2>
          <small>{DEVELOPER} · effective {TERMS_EFFECTIVE}</small>
        </div>
      </header>

      <div className="agreement__body">
        {props.mode === 'accept' && (
          <p className="agreement__intro">Please read and accept this agreement before you use ShieldsVPN.</p>
        )}
        <div className="agreement__headline">
          {TERMS_HEADLINE.map((line) => (
            <p key={line}><strong>{line}</strong></p>
          ))}
        </div>
        {TERMS_SECTIONS.map((s) => (
          <section key={s.title}>
            <h3>{s.title}</h3>
            {s.paragraphs?.map((p) => <p key={p}>{p}</p>)}
            {s.bullets && (
              <ul>
                {s.bullets.map((b) => <li key={b}>{b}</li>)}
              </ul>
            )}
            {s.after?.map((p) => <p key={p}>{p}</p>)}
          </section>
        ))}
      </div>

      <footer className="agreement__actions">
        {props.mode === 'accept' ? (
          <>
            <p>By tapping Agree and continue you confirm that you are 18 or older and accept this agreement and the
              Privacy Policy.</p>
            <div className="actions">
              <button type="button" className="btn btn--ghost" onClick={props.onDecline}>Decline</button>
              <button type="button" className="btn btn--primary agreement__agree" onClick={props.onAccept}>
                Agree and continue
              </button>
            </div>
          </>
        ) : (
          <button type="button" className="btn btn--primary btn--wide" onClick={props.onClose}>Close</button>
        )}
      </footer>
    </div>
  )
}
