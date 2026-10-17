package com.shieldsvpn.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UiJsonTest {
    private val profile = ProfileSummary(
        account = "android", server = "10.0.2.2:51888", serverName = "vpn.e2e.test", tunnelAddress = "10.123.0.2/32",
        expiresEpochSeconds = 1_800_000_000, fullTunnel = false, encryption = "ML-KEM-768 + X25519 · ChaCha20-Poly1305",
        portalUrl = "https://127.0.0.1:8899/", keyAlg = "ML-DSA-65",
    )

    @Test
    fun stateMessageMatchesTheReactBridgeShape() {
        val s = VpnUiState(
            phase = Phase.CONNECTED, active = true, server = "vpn.e2e.test", tunnelAddress = "10.123.0.2/24",
            routes = listOf("10.123.0.0/24"), dns = listOf("9.9.9.9"), connectedSince = 5_000,
        )
        val m = UiJson.state(s, profile, importing = false, permissionNeeded = true, wallNowMs = 1_000_000, elapsedNowMs = 65_000)
        assertEquals("state", m.getString("type"))
        val st = m.getJSONObject("state")
        assertEquals("connected", st.getString("phase"))
        assertTrue(st.getBoolean("active"))
        assertEquals("10.123.0.0/24", st.getJSONArray("routes").getString(0))
        // connected 60 s ago on the monotonic clock -> 60 s before "now" on the wall clock
        assertEquals(940_000L, st.getLong("connectedSince"))
        assertTrue(st.getBoolean("permissionNeeded"))
        val p = st.getJSONObject("profile")
        assertEquals("vpn.e2e.test", p.getString("serverName"))
        assertEquals(1_800_000_000L, p.getLong("expires"))
        assertEquals("ML-DSA-65", p.getString("keyAlg"))
        assertFalse(p.toString().contains("PRIVATE"))  // display data only
        assertTrue(st.isNull("alwaysOn"))               // unknown unless the running service reported it
        val withMode = UiJson.state(s.copy(alwaysOn = true, lockdown = false), profile, false, false, 1, 1)
            .getJSONObject("state")
        assertTrue(withMode.getBoolean("alwaysOn"))
        assertFalse(withMode.getBoolean("lockdown"))
    }

    @Test
    fun noProfileAndNotConnected() {
        val st = UiJson.state(VpnUiState(), null, importing = true, permissionNeeded = false, wallNowMs = 1, elapsedNowMs = 1)
            .getJSONObject("state")
        assertEquals("disconnected", st.getString("phase"))
        assertTrue(st.isNull("profile"))
        assertEquals(0L, st.getLong("connectedSince"))
        assertTrue(st.getBoolean("importing"))
    }

    @Test
    fun onlyKnownCommandsAreAccepted() {
        for (c in UiJson.COMMANDS) assertEquals(c, UiJson.command("""{"type":"$c"}"""))
        assertNull(UiJson.command("""{"type":"exec","cmd":"rm -rf /"}"""))
        assertNull(UiJson.command("not json"))
        assertNull(UiJson.command(null))
        assertNull(UiJson.command("""{"type":"connect","pad":"${"x".repeat(5000)}"}"""))
    }

    @Test
    fun trafficAndNotices() {
        val t = UiJson.traffic("""{"rx_bytes": 1234, "tx_bytes": 56, "rx_packets": 3, "tx_packets": 2}""", 99)!!
        assertEquals(1234L, t.getLong("rx"))
        assertEquals(56L, t.getLong("tx"))
        assertEquals(99L, t.getLong("at"))
        assertNull(UiJson.traffic(null, 1))
        assertNull(UiJson.traffic("{}", 1))
        val n = UiJson.notice(false, "Import failed", "bad key -----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----")
        assertEquals("error", n.getString("kind"))
        assertFalse(n.getString("text").contains("MII"))
        assertEquals(JSONObject().put("type", "insets").put("top", 24.0).put("bottom", 16.0).put("left", 0.0).put("right", 0.0).toString(),
            UiJson.insets(24f, 16f, 0f, 0f).toString())
    }
}
