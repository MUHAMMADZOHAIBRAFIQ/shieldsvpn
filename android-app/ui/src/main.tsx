import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { type Bridge, type NativePort, nativeBridge } from './bridge'
import { mockBridge } from './mock'
import './styles.css'

declare global {
  interface Window {
    /** Injected by the Android app (androidx.webkit addWebMessageListener), only for our own origin. */
    ShieldsBridge?: NativePort
  }
}

const bridge: Bridge = window.ShieldsBridge ? nativeBridge(window.ShieldsBridge) : mockBridge()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App bridge={bridge} />
  </StrictMode>,
)
