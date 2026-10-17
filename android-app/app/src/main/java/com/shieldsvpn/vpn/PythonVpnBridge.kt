package com.shieldsvpn.vpn

/**
 * The Kotlin side of the bridge used by `pqvpn/android_client.py` (`Session(..., bridge)`).
 *
 * All three methods are called from the Python asyncio thread, never from the Android main thread.
 */
interface PythonVpnBridge {
    /** `VpnService.protect()` for the session's UDP socket, so it always uses the physical network. */
    fun protectSocket(fd: Int): Boolean

    /**
     * Build the VPN interface from the validated, authenticated server configuration (JSON produced by
     * `android_client.tunnel_settings`).  Returns a detached file descriptor that Python then owns, or -1.
     */
    fun establishTunnel(settingsJson: String): Int

    /** Connection state changes ("connecting", "connected", "reconnecting", "error", "disconnected"). */
    fun onState(state: String, infoJson: String)
}
