package com.shieldsvpn.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class PortalException(val code: String, message: String, val status: Int = 0) : Exception(message)

/** One Pro plan on sale (`prices` in /api/v1/me), as priced by the administrator.  Display data only. */
data class PriceOption(val period: String, val name: String, val label: String)

/**
 * What the portal says about this device (`GET /api/v1/me`, pqvpn/portal/devices.py `state`).  Display data
 * only; times are Unix seconds.  Pure, so it is unit-tested on the JVM.
 */
data class AccountInfo(
    val plan: String = "free",
    /** Free time left when the portal answered, in seconds: a balance that is used up only while connected. */
    val freeSeconds: Long = 0,
    /** The server was using up that balance when it answered (this device was connected). */
    val freeCounting: Boolean = false,
    /** When the portal answered, on the phone's clock (seconds). */
    val measuredAt: Long = 0,
    val proUntil: Long? = null,
    val email: String = "",
    val signedIn: Boolean = false,
    val canConnect: Boolean = false,
    val reason: String = "",
    val rewardsLeft: Int = 0,
    val freeMinutes: Int = 30,
    val accounts: Boolean = false,
    val admob: Boolean = false,
    /** Free time is granted only on Google's signed callback (production); false = AdMob test mode. */
    val admobVerified: Boolean = true,
    val payments: Boolean = false,
    val priceLabel: String = "",
    /** Pro plans on sale (weekly / monthly / yearly); empty = the portal's single default plan. */
    val prices: List<PriceOption> = emptyList(),
    val renewCertificate: Boolean = false,
    /** Google Play Billing is set up on the portal (Play Store build). */
    val play: Boolean = false,
    /** The Play subscription's product id, and this account's obfuscated reference for purchases (signed in only). */
    val playProduct: String = "",
    val playAccount: String = "",
    /** Free devices: interstitial "connect" (after connecting), "both" (also after disconnecting) or "off". */
    val toggleAds: String = "connect",
    /** At least this many seconds between two such interstitials (0 = every time). */
    val toggleAdGap: Int = 0,
) {
    val pro get() = plan == "premium"

    /** Free time left now, in seconds: it went down since the answer only if the server was counting then. */
    fun freeSecondsLeft(phoneNowSec: Long): Long =
        if (freeCounting) maxOf(0, freeSeconds - maxOf(0, phoneNowSec - measuredAt)) else freeSeconds

    /** When a Free session that is connected now runs out, on the phone's clock (ms); 0 = no limit (Pro). */
    fun stopAtMs(phoneNowMs: Long): Long = if (pro) 0 else phoneNowMs + freeSecondsLeft(phoneNowMs / 1000) * 1000

    /** Show an interstitial for a tap on Connect ([connect] = true) or Disconnect, as the administrator set it. */
    fun toggleAd(connect: Boolean): Boolean =
        !pro && admob && (toggleAds == "both" || (connect && toggleAds == "connect"))

    /**
     * Connect needs an ad first: Free with no time left, and today's rewarded ads are not used up.  The UI says so
     * before the tap (Screen.tsx adBeforeConnect), which makes the tap the opt-in AdMob asks for.
     */
    fun adBeforeConnect(phoneNowSec: Long): Boolean = !pro && freeSecondsLeft(phoneNowSec) <= 0 && admob && rewardsLeft > 0

    companion object {
        fun fromMe(me: JSONObject, phoneNowSec: Long): AccountInfo {
            val f = me.optJSONObject("features") ?: JSONObject()
            val account = me.optJSONObject("account")
            val play = me.optJSONObject("play")
            return AccountInfo(
                plan = if (me.optString("plan") == "premium") "premium" else "free",
                freeSeconds = balance(me),
                // A portal from before the balance sends only an end time on its clock, which always runs.
                freeCounting = if (me.has("free_seconds")) me.optBoolean("free_counting") else true,
                measuredAt = phoneNowSec,
                proUntil = if (me.isNull("pro_until")) null else me.optLong("pro_until"),
                email = account?.optString("email").orEmpty().ifBlank { account?.optString("username").orEmpty() },
                signedIn = account != null,
                canConnect = me.optBoolean("can_connect"),
                reason = me.optString("reason"),
                rewardsLeft = me.optInt("rewards_left_today"),
                freeMinutes = me.optInt("free_minutes", 30),
                accounts = f.optBoolean("accounts"),
                admob = f.optBoolean("admob"),
                admobVerified = f.optBoolean("admob_verified", true),
                payments = f.optBoolean("payments"),
                priceLabel = me.optString("price_label"),
                prices = prices(me.optJSONArray("prices")),
                renewCertificate = me.optJSONObject("device")?.optBoolean("renew") ?: false,
                play = f.optBoolean("play"),
                playProduct = play?.optString("product").orEmpty().take(40),
                playAccount = play?.optString("account").orEmpty().take(64),
                toggleAds = f.optString("toggle_ads", "connect").takeIf { it in TOGGLE_ADS } ?: "connect",
                toggleAdGap = f.optInt("toggle_ad_gap", 0).coerceIn(0, 3600),
            )
        }

        private val TOGGLE_ADS = setOf("connect", "both", "off")

        /** The Free-time balance in a /me answer (seconds); from the end time for portals before the balance. */
        fun balance(me: JSONObject): Long = if (me.has("free_seconds")) maxOf(0, me.optLong("free_seconds"))
            else maxOf(0, me.optLong("free_until") - me.optLong("now", me.optLong("free_until")))

        private val PERIODS = setOf("week", "month", "year")

        /** Known billing periods only, once each, with bounded text: anything else the server sends is dropped. */
        private fun prices(a: JSONArray?): List<PriceOption> = (0 until (a?.length() ?: 0))
            .mapNotNull { i -> a?.optJSONObject(i) }
            .filter { it.optString("period") in PERIODS }
            .map { PriceOption(it.optString("period"), it.optString("name").take(40), it.optString("label").take(60)) }
            .distinctBy { it.period }
    }
}

/**
 * The app side of the portal's app API (pqvpn/portal/api.py), through Python (pqvpn.android_client): the same
 * TLS pinning and request code the Windows app uses.  Every function blocks on the network: call off the main
 * thread.  The device token never leaves the sealed profile secrets except to authenticate these calls.
 */
object Portal {
    val configured: Boolean get() = BuildConfig.PORTAL_URL.isNotBlank()

    private fun result(raw: String): JSONObject {
        val o = JSONObject(raw)
        if (!o.optBoolean("ok")) {
            throw PortalException(o.optString("code", "error"), Redact.text(o.optString("error", "unknown error")),
                o.optInt("status"))
        }
        return o
    }

    /** First start: register this phone (Free, no account) and install its profile. */
    fun enroll(ctx: Context): Pair<ProfileSummary, JSONObject?> {
        val staging = File(ctx.filesDir, "profile-staging").apply { deleteRecursively() }
        try {
            val raw = PythonRuntime.androidClient(ctx).callAttr(
                "enroll_json", BuildConfig.PORTAL_URL, BuildConfig.PORTAL_PIN, BuildConfig.PORTAL_ALLOW_HTTP,
                staging.absolutePath,
            ).toString()
            val o = result(raw)
            val summary = ProfileStore.installEnrolled(ctx, staging, o, o.getString("token"))
            return summary to o.optJSONObject("me")
        } finally {
            staging.deleteRecursively()
        }
    }

    /** A new key and certificate before the current one expires (call while disconnected). */
    fun renew(ctx: Context): ProfileSummary {
        val token = ProfileStore.loadSecrets(ctx).token
        val staging = File(ctx.filesDir, "profile-staging").apply { deleteRecursively() }
        try {
            val raw = PythonRuntime.androidClient(ctx).callAttr(
                "renew_json", BuildConfig.PORTAL_URL, BuildConfig.PORTAL_PIN, BuildConfig.PORTAL_ALLOW_HTTP, token,
                staging.absolutePath,
            ).toString()
            return ProfileStore.installEnrolled(ctx, staging, result(raw), token)
        } finally {
            staging.deleteRecursively()
        }
    }

    /** One API call with this device's token; returns the portal's JSON answer. */
    fun call(ctx: Context, method: String, path: String, body: JSONObject? = null): JSONObject {
        val token = ProfileStore.loadSecrets(ctx).token
        if (token.isEmpty()) throw PortalException("not_enrolled", "This profile was imported from a file; " +
            "accounts and free time need the app's own registration.")
        val raw = PythonRuntime.androidClient(ctx).callAttr(
            "api_json", BuildConfig.PORTAL_URL, BuildConfig.PORTAL_PIN, BuildConfig.PORTAL_ALLOW_HTTP, token,
            method, path, body?.toString() ?: "",
        ).toString()
        return result(raw).getJSONObject("data")
    }
}
