import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import { AccountSheet, ProSheet, type SheetMode } from './account'
import {
  type Account, type AccountResult, type Bridge, type Notice, type Traffic, type VpnState, initialState, noAccount,
} from './bridge'
import { rate } from './format'
import { IconAlert, IconCheck } from './icons'
import { Menu, type ProAction } from './menu'
import { Screen, type TrafficView } from './Screen'

const HISTORY = 30
const emptyTraffic: TrafficView = { down: 0, up: 0, downRate: 0, upRate: 0, downHistory: [], upHistory: [] }

/** Re-render every `ms` milliseconds (0 = never). */
function useNow(ms: number): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!ms) return
    setNow(Date.now())
    const id = window.setInterval(() => setNow(Date.now()), ms)
    return () => window.clearInterval(id)
  }, [ms])
  return now
}

export function App({ bridge }: { bridge: Bridge }) {
  const [state, setState] = useState<VpnState>(initialState)
  const [traffic, setTraffic] = useState<TrafficView>(emptyTraffic)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [account, setAccount] = useState<Account>(noAccount)
  const [sheet, setSheet] = useState<{ mode: SheetMode; note: string } | null>(null)
  const [result, setResult] = useState<AccountResult | null>(null)
  const [menu, setMenu] = useState(false)
  const [proSheet, setProSheet] = useState(false)
  /** The user asked for Pro while signed out: once signed in, go straight on to the plan choice. */
  const proAfterSignIn = useRef(false)
  /** Android's Back closes the top-most overlay (set every render, so it always sees the current state). */
  const closeTop = useRef(() => {})
  const last = useRef<Traffic | null>(null)
  const now = useNow(state.phase === 'connected' || state.profile ? 1000 : 0)

  useEffect(() => {
    const off = bridge.subscribe((msg) => {
      switch (msg.type) {
        case 'state':
          setState(msg.state)
          if (!msg.state.active) {
            last.current = null
            setTraffic(emptyTraffic)
          }
          break
        case 'traffic': {
          const prev = last.current
          last.current = msg
          const down = rate(prev && { v: prev.rx, at: prev.at }, { v: msg.rx, at: msg.at })
          const up = rate(prev && { v: prev.tx, at: prev.at }, { v: msg.tx, at: msg.at })
          setTraffic((t) => ({
            down: msg.rx,
            up: msg.tx,
            downRate: down,
            upRate: up,
            downHistory: [...t.downHistory, down].slice(-HISTORY),
            upHistory: [...t.upHistory, up].slice(-HISTORY),
          }))
          break
        }
        case 'notice':
          if (msg.kind === 'ok') setToast(msg.text)
          else setNotice(msg)
          break
        case 'insets': {
          const root = document.documentElement.style
          root.setProperty('--safe-top', `${msg.top}px`)
          root.setProperty('--safe-bottom', `${msg.bottom}px`)
          root.setProperty('--safe-left', `${msg.left}px`)
          root.setProperty('--safe-right', `${msg.right}px`)
          break
        }
        case 'account':
          setAccount(msg.account)
          break
        case 'accountResult':
          if (msg.op === 'goPro' && msg.code === 'sign_in_required') {
            setResult(null)
            proAfterSignIn.current = true
            setSheet({ mode: 'signIn', note: msg.message })
          } else if (!msg.ok && (msg.op === 'goPro' || msg.op === 'manageSubscription' || msg.op === 'signOut')) {
            setNotice({ kind: 'error', title: msg.op === 'signOut' ? 'Sign out' : 'Pro', text: msg.message })
          } else {
            setResult(msg)
            if (msg.ok && (msg.op === 'signIn' || msg.op === 'verifyEmail')) {
              setToast('You are signed in.')
              // Runs before the sign-in sheet closes itself (its effect sees the same result after this render).
              if (proAfterSignIn.current) setProSheet(true)
              proAfterSignIn.current = false
            }
            if (msg.ok && msg.op === 'deleteAccount') setToast('Your account was deleted.')
          }
          break
        case 'back':
          closeTop.current()
          break
      }
    })
    bridge.send({ type: 'ready' })
    return off
  }, [bridge])

  closeTop.current = () => {
    if (notice) setNotice(null)
    else if (confirmRemove) setConfirmRemove(false)
    else if (sheet) {
      proAfterSignIn.current = false
      setSheet(null)
    } else if (proSheet) setProSheet(false)
    else setMenu(false)
  }
  const overlay = menu || proSheet || sheet !== null || confirmRemove || notice !== null
  useEffect(() => {
    bridge.send({ type: 'overlay', open: overlay })
  }, [bridge, overlay])

  useEffect(() => {
    if (!toast) return
    const id = window.setTimeout(() => setToast(null), 3200)
    return () => window.clearTimeout(id)
  }, [toast])

  const onPower = useCallback(() => {
    if (state.active) bridge.send({ type: 'disconnect' })
    else if (!state.profile && !account.portal) bridge.send({ type: 'importProfile' })
    else bridge.send({ type: 'connect' })   // without a profile, a portal build registers this phone first
  }, [bridge, state.active, state.profile, account.portal])

  const openSheet = (mode: SheetMode, note = '') => {
    setResult(null)
    setSheet({ mode, note })
  }

  const onPro = (action: ProAction) => {
    if (action === 'signUp') {
      proAfterSignIn.current = true
      openSheet('signUp', 'Pro is tied to an account. Create one here, then choose your plan.')
    } else if (action === 'choose') {
      setProSheet(true)
    } else if (action === 'manage') {
      bridge.send({ type: 'manageSubscription' })
    }
  }

  return (
    <>
      <Screen
        state={state}
        traffic={traffic}
        now={now}
        onPower={onPower}
        onImport={() => bridge.send({ type: 'importProfile' })}
        onRemove={() => setConfirmRemove(true)}
        onOpenPortal={() => bridge.send({ type: 'openPortal' })}
        onOpenVpnSettings={() => bridge.send({ type: 'openVpnSettings' })}
        demo={!bridge.native}
        account={account}
        onWatchAd={() => bridge.send({ type: 'watchAd' })}
        onGoPro={(period) => bridge.send({ type: 'goPro', period })}
        onChoosePlan={() => onPro(account.signedIn ? 'choose' : 'signUp')}
        onSignIn={() => openSheet('signIn', 'Pro is tied to an account. The Free plan needs none.')}
        onSignOut={() => bridge.send({ type: 'signOut' })}
        onManage={() => bridge.send({ type: 'manageSubscription' })}
        onDeleteAccount={() => openSheet('delete')}
        onPrivacy={() => bridge.send({ type: 'openPrivacy' })}
        onMenu={() => setMenu(true)}
      />

      {menu && (
        <Menu account={account} hasProfile={state.profile !== null} imports={account.imports}
          locked={state.active || state.importing} onClose={() => setMenu(false)} onPro={onPro}
          onWatchAd={() => bridge.send({ type: 'watchAd' })}
          onSignIn={() => openSheet('signIn', 'Pro is tied to an account. The Free plan needs none.')}
          onSignOut={() => bridge.send({ type: 'signOut' })}
          onDeleteAccount={() => openSheet('delete')}
          onImport={() => bridge.send({ type: 'importProfile' })}
          onVpnSettings={() => bridge.send({ type: 'openVpnSettings' })}
          onPrivacy={() => bridge.send({ type: 'openPrivacy' })} />
      )}

      {proSheet && (
        <ProSheet account={account} onClose={() => setProSheet(false)}
          onChoose={(period) => {
            setProSheet(false)
            bridge.send({ type: 'goPro', period })
          }} />
      )}

      {sheet && (
        <AccountSheet initial={sheet.mode} note={sheet.note} busy={account.busy} result={result}
          send={(m) => bridge.send(m)}
          onClose={() => {
            proAfterSignIn.current = false   // closed without signing in: no plan sheet later
            setSheet(null)
          }} />
      )}

      {confirmRemove && (
        <Modal
          title="Remove profile?"
          tone="danger"
          confirm="Remove"
          onConfirm={() => {
            setConfirmRemove(false)
            bridge.send({ type: 'removeProfile' })
          }}
          onCancel={() => setConfirmRemove(false)}
        >
          This deletes the VPN certificate and the encrypted private key from this phone. You can import a
          profile again later.
        </Modal>
      )}

      {notice && (
        <Modal title={notice.title || 'Something went wrong'} tone="error" confirm="OK" onConfirm={() => setNotice(null)}>
          {notice.text}
        </Modal>
      )}

      <div className={`toast${toast ? ' toast--show' : ''}`} role="status" aria-live="polite">
        {toast && (
          <>
            <IconCheck />
            {toast}
          </>
        )}
      </div>
    </>
  )
}

function Modal(props: {
  title: string
  tone: 'danger' | 'error'
  confirm: string
  onConfirm: () => void
  onCancel?: () => void
  children: ReactNode
}) {
  return (
    <div className="scrim" onClick={props.onCancel ?? props.onConfirm}>
      <div className="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-title" onClick={(e) => e.stopPropagation()}>
        {props.tone === 'error' && (
          <span className="sheet__icon">
            <IconAlert />
          </span>
        )}
        <h2 id="sheet-title">{props.title}</h2>
        <p>{props.children}</p>
        <div className="actions actions--end">
          {props.onCancel && (
            <button type="button" className="btn btn--ghost" onClick={props.onCancel}>
              Cancel
            </button>
          )}
          <button type="button" className={`btn ${props.tone === 'danger' ? 'btn--dangerfill' : 'btn--primary'}`}
            autoFocus onClick={props.onConfirm}>
            {props.confirm}
          </button>
        </div>
      </div>
    </div>
  )
}
