/// <reference types="vitest/config" />
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'

// Strict policy for the packaged UI: only our own bundled script/style, no network at all.  The UI talks
// to the app exclusively through the WebView message bridge (window.ShieldsBridge), never over HTTP.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ')

// Only for `vite build`: the dev server needs inline scripts and a websocket for hot reload.
const csp = (): Plugin => ({
  name: 'shields-csp',
  apply: 'build',
  transformIndexHtml: () => [
    { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP }, injectTo: 'head-prepend' },
  ],
})

export default defineConfig({
  plugins: [react(), csp()],
  base: './', // served from https://appassets.androidplatform.net/assets/ui/ inside the app
  build: {
    // Gradle adds this directory to the APK's assets (android-app/app/build.gradle.kts).
    outDir: fileURLToPath(new URL('../app/build/generated/ui-assets/ui', import.meta.url)),
    emptyOutDir: true,
    target: 'chrome89', // Android System WebView 89+ (2021); WebMessageListener itself needs 82+
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  test: {
    environment: 'node',
  },
})
