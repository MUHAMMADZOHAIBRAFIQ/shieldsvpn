import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import { type Bridge, type Notice, type Traffic, type VpnState, initialState } from './bridge'
import { rate } from './format'
import { IconAlert, IconCheck } from './icons'
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
      }
    })
    bridge.send({ type: 'ready' })
    return off
  }, [bridge])

  useEffect(() => {
    if (!toast) return
    const id = window.setTimeout(() => setToast(null), 3200)
    return () => window.clearTimeout(id)
  }, [toast])

  const onPower = useCallback(() => {
    if (state.active) bridge.send({ type: 'disconnect' })
    else if (!state.profile) bridge.send({ type: 'importProfile' })
    else bridge.send({ type: 'connect' })
  }, [bridge, state.active, state.profile])

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
      />

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
