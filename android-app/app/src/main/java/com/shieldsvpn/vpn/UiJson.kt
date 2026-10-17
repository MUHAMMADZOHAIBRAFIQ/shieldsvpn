package com.shieldsvpn.vpn

import org.json.JSONArray
import org.json.JSONObject

/**
 * The JSON messages exchanged with the React UI (android-app/ui/src/bridge.ts).  Pure, so it is unit-tested
 * on the JVM.  Only display data crosses the bridge: never keys, certificates or file paths.
 */
object UiJson {
    /** Commands the UI may send; anything else is ignored. */
    val COMMANDS = setOf("ready", "connect", "disconnect", "importProfile", "removeProfile", "openPortal", "openVpnSettings")

    fun command(raw: String?): String? {
        if (raw == null || raw.length > 4096) return null
        val type = runCatching { JSONObject(raw).getString("type") }.getOrNull()
        return type?.takeIf { it in COMMANDS }
    }

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
