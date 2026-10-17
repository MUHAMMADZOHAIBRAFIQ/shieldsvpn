import { describe, expect, it } from 'vitest'
import {
  daysLeft,
  encryptionParts,
  formatBytes,
  formatDuration,
  formatRate,
  phaseInfo,
  rate,
  subtitle,
} from './format'

describe('formatting', () => {
  it('formats byte counts and rates', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(50 * 1024 * 1024)).toBe('50 MB')
    expect(formatBytes(-5)).toBe('0 B')
    expect(formatRate(2048)).toBe('2.0 KB/s')
  })

  it('formats durations as hh:mm:ss', () => {
    expect(formatDuration(0)).toBe('00:00:00')
    expect(formatDuration(61_000)).toBe('00:01:01')
    expect(formatDuration(3_725_999)).toBe('01:02:05')
    expect(formatDuration(-1000)).toBe('00:00:00')
  })

  it('counts days until expiry', () => {
    const now = Date.UTC(2026, 9, 17)
    expect(daysLeft(now / 1000 + 10 * 86400 + 5, now)).toBe(10)
    expect(daysLeft(now / 1000 - 60, now)).toBe(-1)
  })

  it('splits the encryption label into chips', () => {
    expect(encryptionParts('ML-KEM-768 + X25519 · ChaCha20-Poly1305')).toEqual(['ML-KEM-768', 'X25519', 'ChaCha20-Poly1305'])
    expect(encryptionParts('ML-KEM-1024 · AES-256-GCM')).toEqual(['ML-KEM-1024', 'AES-256-GCM'])
    expect(encryptionParts('')).toEqual([])
  })

  it('computes rates and ignores counter resets', () => {
    expect(rate(null, { v: 100, at: 1000 })).toBe(0)
    expect(rate({ v: 0, at: 0 }, { v: 2048, at: 2000 })).toBe(1024)
    expect(rate({ v: 5000, at: 0 }, { v: 10, at: 1000 })).toBe(0) // new session restarted the counters
  })
})

describe('phases', () => {
  it('maps every phase to a label and tone', () => {
    expect(phaseInfo('connected')).toEqual({ label: 'Connected', tone: 'on', busy: false })
    expect(phaseInfo('reconnecting').busy).toBe(true)
    expect(phaseInfo('error').tone).toBe('error')
  })

  it('explains what to do next', () => {
    expect(subtitle('disconnected', false, false, false)).toMatch(/Import/)
    expect(subtitle('disconnected', false, true, false)).toMatch(/Tap to connect/)
    expect(subtitle('error', true, true, false)).toMatch(/Retrying/)
    expect(subtitle('error', false, true, false)).toMatch(/try again/)
    expect(subtitle('connected', true, true, true)).toMatch(/Checking/)
  })
})
