package com.shieldsvpn.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AccountTest {
    // The shape pqvpn/portal/devices.py `state()` returns for GET /api/v1/me.
    private fun me(plan: String = "free", freeUntil: Long = 1_000_600, now: Long = 1_000_000, account: Boolean = false) =
        JSONObject(
            """{"now": $now, "plan": "$plan", "free_until": $freeUntil, "pro_until": ${if (plan == "premium") 1_900_000 else "null"},
               "can_connect": true, "reason": "", "free_minutes": 30, "rewards_left_today": 12,
               "account": ${if (account) """{"username": "sam", "email": "sam@example.com"}""" else "null"},
               "device": {"subject": "d-abc", "renew": false},
               "features": {"accounts": true, "admob": true, "admob_verified": false, "web_ads": false, "payments": true},
               "price_label": "USD 4.99 / month",
               "prices": [{"period": "week", "name": "Weekly", "amount": "1.99", "currency": "USD", "label": "USD 1.99 / week"},
                          {"period": "month", "name": "Monthly", "label": "USD 4.99 / month"},
                          {"period": "day", "name": "Daily", "label": "not a Paddle period"},
                          {"period": "month", "name": "Again", "label": "duplicate"}, "junk"]}""",
        )

    @Test
    fun freeTimeIsJudgedByTheServerClock() {
        // The phone's clock is 100 s behind the server: 600 s granted at server time 1_000_000.
        val a = AccountInfo.fromMe(me(), phoneNowSec = 999_900)
        assertEquals(100L, a.clockSkew)
        assertEquals(600L, a.freeSecondsLeft(999_900))
        assertEquals(0L, a.freeSecondsLeft(1_000_600))
        assertEquals((1_000_600L - 100) * 1000, a.stopAtMs())   // the service stops on the phone's clock
        assertFalse(a.pro)
        assertFalse(a.admobVerified)
        assertTrue(a.payments)
        assertEquals("USD 4.99 / month", a.priceLabel)
    }

    @Test
    fun connectPlaysAnAdOnlyWhenFreeTimeIsUsedUpAndAdsAreLeft() {
        val now = 1_000_000L
        assertFalse(AccountInfo.fromMe(me(freeUntil = now + 60), now).adBeforeConnect(now))      // time left
        assertTrue(AccountInfo.fromMe(me(freeUntil = now - 1), now).adBeforeConnect(now))        // used up
        assertFalse(AccountInfo.fromMe(me(plan = "premium", freeUntil = 0), now).adBeforeConnect(now))  // Pro
        val noneLeft = AccountInfo.fromMe(me(freeUntil = 0), now).copy(rewardsLeft = 0)
        assertFalse(noneLeft.adBeforeConnect(now))                                                // today's ads used
        assertFalse(AccountInfo.fromMe(me(freeUntil = 0), now).copy(admob = false).adBeforeConnect(now))  // no ads
    }

    @Test
    fun proPlansKeepOnlyKnownPeriodsOnce() {
        val a = AccountInfo.fromMe(me(), 1_000_000)
        assertEquals(listOf(PriceOption("week", "Weekly", "USD 1.99 / week"), PriceOption("month", "Monthly", "USD 4.99 / month")),
            a.prices)
        assertEquals(emptyList<PriceOption>(), AccountInfo.fromMe(JSONObject("""{"prices": "many"}"""), 0).prices)
        val m = UiJson.account(true, a, busy = false, wallNowMs = 1).getJSONObject("account").getJSONArray("prices")
        assertEquals(2, m.length())
        val week = m.getJSONObject(0)
        assertEquals(listOf("week", "Weekly", "USD 1.99 / week"), listOf("period", "name", "label").map(week::getString))
        assertEquals(3, week.length())   // display data only
        val raw = """{"type":"goPro","period":"year-and-then-some"}"""
        assertEquals("goPro", UiJson.command(raw))
        assertEquals("year-and", UiJson.field(raw, "period", 8))   // bounded; MainActivity sends only offered periods
    }

    @Test
    fun playStoreFieldsAndCommands() {
        val me = JSONObject("""{"plan": "free", "features": {"play": true, "payments": true},
            "play": {"product": "shieldsvpn_pro", "account": "0123456789abcdef0123456789abcdef"}}""")
        val a = AccountInfo.fromMe(me, 0)
        assertTrue(a.play)
        assertEquals("shieldsvpn_pro", a.playProduct)
        assertEquals(32, a.playAccount.length)
        assertFalse(AccountInfo.fromMe(JSONObject("{}"), 0).play)
        val m = UiJson.account(true, a, busy = false, wallNowMs = 1, imports = false, privacy = true).getJSONObject("account")
        assertFalse(m.getBoolean("imports"))
        assertTrue(m.getBoolean("privacy"))
        assertFalse(m.toString().contains("0123456789abcdef"))   // the account reference stays in Kotlin
        assertTrue(UiJson.account(false, null, busy = false, wallNowMs = 1).getJSONObject("account").getBoolean("imports"))
        assertEquals("deleteAccount", UiJson.command("""{"type":"deleteAccount","password":"x","code":""}"""))
        assertEquals("openPrivacy", UiJson.command("""{"type":"openPrivacy"}"""))
    }

    @Test
    fun playPlanPeriods() {
        assertEquals("week", PlayPlans.period("P1W"))
        assertEquals("month", PlayPlans.period("P1M"))
        assertEquals("year", PlayPlans.period("P1Y"))
        assertNull(PlayPlans.period("P3M"))   // other periods are not offered
        val options = PlayPlans.options(listOf(PlayPlan("year", PlayPlans.label("Rs 9,000.00", "year"), "tok")))
        assertEquals(listOf(PriceOption("year", "Yearly", "Rs 9,000.00 / year")), options)
    }

    @Test
    fun proHasNoStopTimeAndShowsTheAccount() {
        val a = AccountInfo.fromMe(me(plan = "premium", account = true), 1_000_000)
        assertTrue(a.pro)
        assertEquals(0L, a.stopAtMs())
        assertTrue(a.signedIn)
        assertEquals("sam@example.com", a.email)
        assertEquals(1_900_000L, a.proUntil)
        assertNull(AccountInfo.fromMe(me(), 1_000_000).proUntil)
        assertEquals("free", AccountInfo.fromMe(JSONObject("""{"plan": "anything-else"}"""), 0).plan)
    }

    @Test
    fun accountMessageMatchesTheReactBridgeShape() {
        val a = AccountInfo.fromMe(me(account = true), 1_000_000)
        val m = UiJson.account(true, a, busy = false, wallNowMs = 1_000_000_000).getJSONObject("account")
        assertTrue(m.getBoolean("available"))
        assertTrue(m.getBoolean("known"))
        assertEquals(600L, m.getLong("freeSecondsLeft"))
        assertEquals(1_000_000_000L, m.getLong("at"))
        assertEquals("sam@example.com", m.getString("email"))
        assertTrue(m.getBoolean("ads"))
        assertFalse(m.toString().contains("d-abc"))   // display data only: no device name, token or key
        val unknown = UiJson.account(false, null, busy = true, wallNowMs = 5).getJSONObject("account")
        assertFalse(unknown.getBoolean("known"))
        assertFalse(unknown.has("plan"))
    }

    @Test
    fun commandFieldsAreBoundedAndResultsRedacted() {
        val raw = """{"type":"signIn","login":"sam@example.com","password":"${"p".repeat(300)}"}"""
        assertEquals("signIn", UiJson.command(raw))
        assertEquals("sam@example.com", UiJson.field(raw, "login"))
        assertEquals(128, UiJson.field(raw, "password", 128).length)
        assertEquals("", UiJson.field(raw, "code"))
        assertEquals("", UiJson.field("not json", "login"))
        for (c in listOf("watchAd", "signUp", "verifyEmail", "forgotPassword", "resetPassword", "signOut", "goPro",
            "manageSubscription", "refreshAccount")) {
            assertEquals(c, UiJson.command("""{"type":"$c"}"""))
        }
        val r = UiJson.accountResult("signIn", false, "invalid", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
        assertEquals("accountResult", r.getString("type"))
        assertFalse(r.getString("message").contains("PRIVATE KEY-----\nabc"))
    }
}
