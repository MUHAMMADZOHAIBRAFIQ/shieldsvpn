package com.shieldsvpn.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StateMapperTest {
    @Test
    fun fullLifecycle() {
        var s = VpnUiState(Phase.PREPARING, active = true)
        s = StateMapper.fromPython(s, "connecting", JSONObject("""{"server": "vpn.test", "endpoint": "203.0.113.1:51820"}"""), 0)
        assertEquals(Phase.CONNECTING, s.phase)
        assertEquals("vpn.test", s.server)

        s = StateMapper.fromPython(
            s, "connected",
            JSONObject("""{"server": "vpn.test", "suite": "MLKEM768-X25519_CHACHA20POLY1305_SHA384",
                "encryption": "ML-KEM-768 + X25519 · ChaCha20-Poly1305", "tunnel_address": "10.66.0.2/24",
                "routes": ["10.66.0.0/24"], "dns": ["10.66.0.1"], "full_tunnel": false, "key_alg": "ML-DSA-65"}"""),
            1000,
        )
        assertEquals(Phase.CONNECTED, s.phase)
        assertTrue(s.active)
        assertEquals("10.66.0.2/24", s.tunnelAddress)
        assertEquals("ML-KEM-768 + X25519 · ChaCha20-Poly1305", s.encryption)
        assertEquals(listOf("10.66.0.0/24"), s.routes)
        assertEquals(1000L, s.connectedSince)

        s = StateMapper.fromPython(s, "reconnecting", JSONObject("{}"), 5000)
        assertEquals(Phase.RECONNECTING, s.phase)
        s = StateMapper.fromPython(s, "connected", JSONObject("""{"server": "vpn.test"}"""), 9000)
        assertEquals(1000L, s.connectedSince)            // the session time survives a reconnect
        assertEquals("10.66.0.2/24", s.tunnelAddress)     // and so do the tunnel details

        s = StateMapper.fromPython(s, "disconnected", JSONObject("{}"), 9500)
        assertEquals(Phase.CONNECTED, s.phase)            // the service reports the end itself
    }

    @Test
    fun errorsAreRedactedAndFinishMapsCorrectly() {
        val s = StateMapper.fromPython(
            VpnUiState(Phase.CONNECTING, active = true), "error",
            JSONObject().put("message", "boom -----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY----- done"), 0,
        )
        assertEquals(Phase.ERROR, s.phase)
        assertTrue(s.active)                               // the session keeps retrying
        assertFalse(s.message.contains("MIIabc"))

        val failed = StateMapper.finished(s, "Cannot find the server", userStopped = false)
        assertEquals(Phase.ERROR, failed.phase)
        assertFalse(failed.active)
        val stopped = StateMapper.finished(s, "Cannot find the server", userStopped = true)
        assertEquals(Phase.DISCONNECTED, stopped.phase)
        assertEquals(Phase.DISCONNECTED, StateMapper.finished(s, "", userStopped = false).phase)
    }

    @Test
    fun redaction() {
        assertEquals("key [redacted]", Redact.text("key " + "A".repeat(64)))
        assertEquals("Cannot find the server", Redact.pythonError(RuntimeException("com.chaquo.python.PyException: ProfileError: Cannot find the server")))
    }
}
