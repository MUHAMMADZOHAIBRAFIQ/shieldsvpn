package com.shieldsvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelConfigTest {
    // Exactly what pqvpn.android_client.tunnel_settings() produces for the default split-tunnel profile.
    private val split = """{"session": "vpn.example.com", "mtu": 1420,
        "addresses": [{"address": "10.66.0.2", "prefix": 24}],
        "routes": [{"address": "10.66.0.0", "prefix": 24}], "dns": ["10.66.0.1"],
        "full_tunnel": false, "blocked_families": [], "bypass_families": ["ipv6"], "dropped": []}"""

    @Test
    fun parsesSplitTunnel() {
        val c = TunnelConfig.fromJson(split)
        assertEquals("vpn.example.com", c.session)
        assertEquals(1420, c.mtu)
        assertEquals(listOf(IpPrefix("10.66.0.2", 24)), c.addresses)
        assertEquals(listOf(IpPrefix("10.66.0.0", 24)), c.routes)
        assertEquals(listOf("10.66.0.1"), c.dns)
        assertFalse(c.fullTunnel)
        assertEquals(setOf("ipv6"), c.bypassFamilies)
    }

    @Test
    fun parsesFullTunnelWithIpv6Blocked() {
        val c = TunnelConfig.fromJson(
            split.replace(""""routes": [{"address": "10.66.0.0", "prefix": 24}]""",
                """"routes": [{"address": "0.0.0.0", "prefix": 0}]""")
                .replace(""""full_tunnel": false""", """"full_tunnel": true""")
                .replace(""""blocked_families": [], "bypass_families": ["ipv6"]""",
                    """"blocked_families": ["ipv6"], "bypass_families": []"""),
        )
        assertTrue(c.fullTunnel)
        assertEquals(setOf("ipv6"), c.blockedFamilies)
        assertTrue(c.bypassFamilies.isEmpty())
    }

    @Test
    fun rejectsMalformedSettings() {
        val bad = listOf(
            split.replace("\"mtu\": 1420", "\"mtu\": 576"),
            split.replace("\"10.66.0.2\"", "\"vpn.example.com\""),          // never a host name (no DNS lookups)
            split.replace("\"prefix\": 24}]", "\"prefix\": 33}]"),
            split.replace("""[{"address": "10.66.0.2", "prefix": 24}]""", "[]"),
            split.replace(""""routes": [{"address": "10.66.0.0", "prefix": 24}]""", """"routes": []"""),
            split.replace("\"10.66.0.1\"", "\"999.1.1.1\""),
            split.replace("\"bypass_families\": [\"ipv6\"]", "\"bypass_families\": [\"ipv4\"]"),  // ipv4 is configured
            split.replace("\"bypass_families\": [\"ipv6\"]", "\"bypass_families\": [\"ipx\"]"),
        )
        for (json in bad) assertThrows(json, Exception::class.java) { TunnelConfig.fromJson(json) }
    }

    @Test
    fun ipLiterals() {
        assertTrue(TunnelConfig.isIpLiteral("10.0.0.1"))
        assertTrue(TunnelConfig.isIpLiteral("fd00::1"))
        assertTrue(TunnelConfig.isIpLiteral("::"))
        assertFalse(TunnelConfig.isIpLiteral("256.0.0.1"))
        assertFalse(TunnelConfig.isIpLiteral("example.com"))
        assertFalse(TunnelConfig.isIpLiteral("1.2.3"))
    }
}
