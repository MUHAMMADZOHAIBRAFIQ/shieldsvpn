package com.shieldsvpn.vpn

import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

enum class Phase { DISCONNECTED, PREPARING, CONNECTING, CONNECTED, RECONNECTING, ERROR, DISCONNECTING }

/** Everything the screen and the notification show. */
data class VpnUiState(
    val phase: Phase = Phase.DISCONNECTED,
    /** True while the service runs a session (so the button means "Disconnect"). */
    val active: Boolean = false,
    val message: String = "",
    val server: String = "",
    val endpoint: String = "",
    val tunnelAddress: String = "",
    val encryption: String = "",
    val keyAlg: String = "",
    val routes: List<String> = emptyList(),
    val dns: List<String> = emptyList(),
    val fullTunnel: Boolean = false,
    /** SystemClock.elapsedRealtime() when the tunnel first came up, 0 when not connected. */
    val connectedSince: Long = 0L,
    /** Android always-on VPN for this app, as reported by the running service (null = unknown). */
    val alwaysOn: Boolean? = null,
    /** Android "Block connections without VPN" (system kill switch), as reported by the service. */
    val lockdown: Boolean? = null,
)

/** Maps the Python session's state reports onto UI state.  Pure, so it is unit-tested on the JVM. */
object StateMapper {
    fun fromPython(prev: VpnUiState, state: String, info: JSONObject, nowMs: Long): VpnUiState = when (state) {
        "connecting" -> prev.copy(
            phase = Phase.CONNECTING, active = true, message = "",
            server = info.optString("server", prev.server), endpoint = info.optString("endpoint", prev.endpoint),
        )
        "reconnecting" -> prev.copy(phase = Phase.RECONNECTING, active = true, message = "")
        "connected" -> prev.copy(
            phase = Phase.CONNECTED, active = true, message = "",
            server = info.optString("server", prev.server),
            endpoint = info.optString("endpoint", prev.endpoint),
            tunnelAddress = info.optString("tunnel_address", "").ifBlank { info.optString("address", prev.tunnelAddress) },
            encryption = info.optString("encryption", "").ifBlank { info.optString("suite", prev.encryption) },
            keyAlg = info.optString("key_alg", prev.keyAlg),
            routes = info.optJSONArray("routes")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: prev.routes,
            dns = info.optJSONArray("dns")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: prev.dns,
            fullTunnel = if (info.has("full_tunnel")) info.optBoolean("full_tunnel") else prev.fullTunnel,
            connectedSince = if (prev.connectedSince > 0) prev.connectedSince else nowMs,
        )
        "error" -> prev.copy(phase = Phase.ERROR, active = true, message = Redact.text(info.optString("message")))
        // "disconnected" is reported by the service itself once the session thread has finished.
        else -> prev
    }

    /** Final state once the session has ended. */
    fun finished(prev: VpnUiState, error: String, userStopped: Boolean): VpnUiState =
        if (error.isNotBlank() && !userStopped) {
            VpnUiState(phase = Phase.ERROR, active = false, message = Redact.text(error))
        } else {
            VpnUiState(phase = Phase.DISCONNECTED, active = false)
        }
}

/** Process-wide state holder.  Updates may come from any thread; listeners run on the main thread. */
object VpnStateStore {
    private val main = Handler(Looper.getMainLooper())
    private val listeners = CopyOnWriteArrayList<(VpnUiState) -> Unit>()

    @Volatile
    var state = VpnUiState()
        private set

    fun update(transform: (VpnUiState) -> VpnUiState) {
        val snapshot: VpnUiState
        synchronized(this) {
            state = transform(state)
            snapshot = state
        }
        main.post { listeners.forEach { it(snapshot) } }
    }

    fun observe(listener: (VpnUiState) -> Unit) {
        listeners += listener
        listener(state)
    }

    fun remove(listener: (VpnUiState) -> Unit) {
        listeners -= listener
    }
}
