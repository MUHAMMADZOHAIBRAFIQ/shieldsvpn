package com.shieldsvpn.vpn

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileBindingTest {
    @Test
    fun secretsMustBelongToTheInstalledCertificate() {
        val secrets = JSONObject().put("key_pem", "x").put("serial", "A1B2")
        assertTrue(ProfileStore.secretsMatchProfile(secrets, "a1b2"))          // hex, case-insensitive
        assertFalse(ProfileStore.secretsMatchProfile(secrets, "ffff"))         // interrupted replacement
        assertTrue(ProfileStore.secretsMatchProfile(JSONObject().put("key_pem", "x"), "ffff"))  // pre-binding install
        assertTrue(ProfileStore.secretsMatchProfile(secrets, ""))              // summary without serial
    }
}
