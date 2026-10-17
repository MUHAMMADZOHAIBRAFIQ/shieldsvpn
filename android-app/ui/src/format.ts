import type { Phase } from './bridge'

export type Tone = 'off' | 'busy' | 'on' | 'error'

export interface PhaseInfo {
  label: string
  tone: Tone
  busy: boolean
}

const PHASES: Record<Phase, PhaseInfo> = {
  disconnected: { label: 'Disconnected', tone: 'off', busy: false },
  preparing: { label: 'Preparing VPN', tone: 'busy', busy: true },
  connecting: { label: 'Connecting', tone: 'busy', busy: true },
  connected: { label: 'Connected', tone: 'on', busy: false },
  reconnecting: { label: 'Reconnecting', tone: 'busy', busy: true },
  error: { label: 'Error', tone: 'error', busy: false },
  disconnecting: { label: 'Disconnecting', tone: 'busy', busy: true },
}

export const phaseInfo = (phase: Phase): PhaseInfo => PHASES[phase]

/** One line under the status headline. */
export function subtitle(phase: Phase, active: boolean, hasProfile: boolean, importing: boolean): string {
  if (importing) return 'Checking your profile…'
  switch (phase) {
    case 'disconnected':
      return hasProfile ? 'Tap to connect. Your traffic is not protected.' : 'Import your ShieldsVPN profile to get started.'
    case 'preparing':
      return 'Starting the secure engine…'
    case 'connecting':
      return 'Running the post-quantum handshake…'
    case 'connected':
      return 'Post-quantum protection is on.'
    case 'reconnecting':
      return 'Connection dropped. Restoring it; your traffic stays in the tunnel.'
    case 'disconnecting':
      return 'Closing the tunnel…'
    case 'error':
      return active ? 'Retrying automatically. Tap to stop.' : 'Tap to try again.'
  }
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB']

export function formatBytes(n: number): string {
  let v = Math.max(0, n)
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  return i === 0 ? `${Math.round(v)} B` : `${v < 10 ? v.toFixed(1) : Math.round(v)} ${UNITS[i]}`
}

export const formatRate = (bytesPerSecond: number): string => `${formatBytes(bytesPerSecond)}/s`

export function formatDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000))
  const pad = (x: number) => String(x).padStart(2, '0')
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`
}

/** Whole days until the certificate expires (negative = expired). */
export const daysLeft = (expiresSeconds: number, nowMs: number): number =>
  Math.floor((expiresSeconds * 1000 - nowMs) / 86_400_000)

export function formatDate(expiresSeconds: number): string {
  return new Date(expiresSeconds * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

/** "ML-KEM-768 + X25519 · ChaCha20-Poly1305" -> ["ML-KEM-768", "X25519", "ChaCha20-Poly1305"]. */
export const encryptionParts = (encryption: string): string[] =>
  encryption.split(/\s*[+·]\s*/).map((p) => p.trim()).filter(Boolean)

/** Bytes per second between two samples (0 when unknown or the counters were reset). */
export function rate(prev: { v: number; at: number } | null, next: { v: number; at: number }): number {
  if (!prev || next.at <= prev.at || next.v < prev.v) return 0
  return ((next.v - prev.v) * 1000) / (next.at - prev.at)
}
