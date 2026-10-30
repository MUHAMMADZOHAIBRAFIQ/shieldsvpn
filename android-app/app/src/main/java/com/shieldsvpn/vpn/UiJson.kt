package com.shieldsvpn.vpn

import org.json.JSONArray
import org.json.JSONObject

/**
 * The JSON messages exchanged with the React UI (android-app/ui/src/bridge.ts).  Pure, so it is unit-tested
 * on the JVM.  Only display data crosses the bridge: never keys, certificates or file paths.
 */
object UiJson {
    /** Commands the UI may send; anything else is ignored. */
    val COMMANDS = setOf(
        "ready", "connect", "disconnect", "importProfile", "removeProfile", "openPortal", "openVpnSettings",
        // Free with ads / sign-in / Pro (Portal.kt):
        "refreshAccount", "watchAd", "signIn", "signUp", "verifyEmail", "forgotPassword", "resetPassword",
        "signOut", "goPro", "manageSubscription",
        // Google Play requirements: account deletion in the app, and the privacy policy linked from the app.
        "deleteAccount", "openPrivacy",
        // A menu or sheet is open ({open: true}): Android's Back closes it (a "back" message) instead of the app.
        "overlay",
    )

    fun command(raw: String?): String? {
        if (raw == null || raw.length > 4096) return null
        val type = runCatching { JSONObject(raw).getString("type") }.getOrNull()
        return type?.takeIf { it in COMMANDS }
    }

    /** A string field of a command (what the user typed), trimmed to [max] characters; "" if absent. */
    fun field(raw: String?, name: String, max: Int = 254): String {
        if (raw == null || raw.length > 4096) return ""
        val v = runCatching { JSONObject(raw).optString(name, "") }.getOrDefault("")
        return v.take(max)
    }

    /** A boolean field of a command; only a JSON `true` counts (a string "true" or anything else is false). */
    fun flag(raw: String?, name: String): Boolean {
        if (raw == null || raw.length > 4096) return false
        return runCatching { JSONObject(raw).opt(name) == true }.getOrDefault(false)
    }

    /** Back was pressed while the UI had an overlay open: it closes the top-most one. */
    fun back(): JSONObject = JSONObject().put("type", "back")

    /**
     * The plan card: what the portal says about this device.  [available] = this build talks to a portal and
     * the installed profile was registered by the app (not imported from a ZIP).  [imports] = profile files may be
     * imported (not in the Play Store build); [privacy] = a privacy-policy link exists.
     */
    fun account(
        available: Boolean,
        info: AccountInfo?,
        busy: Boolean,
        wallNowMs: Long,
        portal: Boolean = available,
        imports: Boolean = true,
        privacy: Boolean = false,
    ): JSONObject {
        val a = JSONObject().put("available", available).put("busy", busy).put("known", info != null)
            .put("portal", portal)   // this build registers itself with a portal (no ZIP import needed)
            .put("imports", imports)
            .put("privacy", privacy)
            .put("at", wallNowMs)   // the UI counts the free time down from this moment
        if (info != null) {
            a.put("plan", info.plan)
                .put("freeSecondsLeft", info.freeSecondsLeft(wallNowMs / 1000))
                .put("proUntil", info.proUntil ?: JSONObject.NULL)
                .put("signedIn", info.signedIn)
                .put("email", info.email)
                .put("canConnect", info.canConnect)
                .put("reason", info.reason)
                .put("rewardsLeft", info.rewardsLeft)
                .put("freeMinutes", info.freeMinutes)
                .put("accounts", info.accounts)
                .put("ads", info.admob)
                .put("payments", info.payments)
                .put("priceLabel", info.priceLabel)
                .put("prices", JSONArray(info.prices.map {
                    JSONObject().put("period", it.period).put("name", it.name).put("label", it.label)
                }))
        }
        return JSONObject().put("type", "account").put("account", a)
    }

    /** Outcome of a sign-in / sign-up / reset step, so the form can move on or show the error. */
    fun accountResult(op: String, ok: Boolean, code: String = "", message: String = ""): JSONObject = JSONObject()
        .put("type", "accountResult").put("op", op).put("ok", ok).put("code", code).put("message", Redact.text(message))

    /**
     * @param wallNowMs System.currentTimeMillis(), @param elapsedNowMs SystemClock.elapsedRealtime(): the UI's
     * timer needs wall-clock time, the service records the monotonic clock.
     */
    fun state(
        s: VpnUiState,
        profile: ProfileSummary?,
        importing: Boolean,
        permissionNeeded: Boolean,
        wallNowMs: Long,
        elapsedNowMs: Long,
    ): JSONObject = JSONObject()
        .put("type", "state")
        .put(
            "state",
            JSONObject()
                .put("phase", s.phase.name.lowercase())
                .put("active", s.active)
                .put("message", s.message)
                .put("server", s.server)
                .put("endpoint", s.endpoint)
                .put("tunnelAddress", s.tunnelAddress)
                .put("encryption", s.encryption)
                .put("keyAlg", s.keyAlg)
                .put("routes", JSONArray(s.routes))
                .put("dns", JSONArray(s.dns))
                .put("fullTunnel", s.fullTunnel)
                .put("connectedSince", if (s.connectedSince > 0) wallNowMs - (elapsedNowMs - s.connectedSince) else 0L)
                .put("importing", importing)
                .put("permissionNeeded", permissionNeeded)
                .put("alwaysOn", s.alwaysOn ?: JSONObject.NULL)
                .put("lockdown", s.lockdown ?: JSONObject.NULL)
                .put("profile", profile?.let(::profile) ?: JSONObject.NULL),
        )

    fun profile(p: ProfileSummary): JSONObject = JSONObject()
        .put("account", p.account)
        .put("server", p.server)
        .put("serverName", p.serverName)
        .put("tunnelAddress", p.tunnelAddress)
        .put("expires", p.expiresEpochSeconds)
        .put("fullTunnel", p.fullTunnel)
        .put("encryption", p.encryption)
        .put("portalUrl", p.portalUrl)
        .put("keyAlg", p.keyAlg)
        .put("enrolled", p.enrolled)

    /** `Session.stats_json()` output -> a traffic message, or null if it cannot be read. */
    fun traffic(statsJson: String?, wallNowMs: Long): JSONObject? = runCatching {
        val o = JSONObject(statsJson!!)
        JSONObject().put("type", "traffic").put("rx", o.getLong("rx_bytes")).put("tx", o.getLong("tx_bytes")).put("at", wallNowMs)
    }.getOrNull()

    fun notice(ok: Boolean, title: String, text: String): JSONObject = JSONObject()
        .put("type", "notice").put("kind", if (ok) "ok" else "error").put("title", title).put("text", Redact.text(text))

    fun insets(top: Float, bottom: Float, left: Float, right: Float): JSONObject = JSONObject()
        .put("type", "insets").put("top", top.toDouble()).put("bottom", bottom.toDouble())
        .put("left", left.toDouble()).put("right", right.toDouble())
}
