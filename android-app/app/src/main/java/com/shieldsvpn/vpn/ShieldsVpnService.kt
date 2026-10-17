package com.shieldsvpn.vpn

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.system.OsConstants
import android.util.Log
import com.chaquo.python.PyObject
import org.json.JSONObject

/**
 * The Android VPN service.  It owns one pqvpn `Session` (Python) per connection:
 *
 *   1. startSession(): consent check (VpnService.prepare) -> foreground notification -> worker thread.
 *   2. Worker thread: start Python, decrypt the profile secrets, `Session(...).run()` (blocks).
 *   3. Python protects its UDP socket (protectSocket), runs the post-quantum handshake, validates the
 *      server's authenticated configuration and only then calls establishTunnel(): the TUN interface is
 *      created once, with the real address/routes/DNS, and its fd is handed to Python.
 *   4. Disconnect / revoke / destroy -> `Session.stop()`; Python closes the TUN fd and the UDP socket,
 *      the worker returns, the service leaves the foreground and stops.
 */
class ShieldsVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "com.shieldsvpn.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "com.shieldsvpn.vpn.action.DISCONNECT"
        private const val TAG = "ShieldsVpnService"

        fun connect(ctx: Context) {
            ctx.startService(Intent(ctx, ShieldsVpnService::class.java).setAction(ACTION_CONNECT))
        }

        fun disconnect(ctx: Context) {
            ctx.startService(Intent(ctx, ShieldsVpnService::class.java).setAction(ACTION_DISCONNECT))
        }

        @Volatile private var activeSession: PyObject? = null

        /** Traffic counters of the running session (`Session.stats_json()`), or null.  Call off the main thread. */
        fun trafficJson(): String? =
            activeSession?.let { s -> runCatching { s.callAttr("stats_json").toString() }.getOrNull() }
    }

    private val main = Handler(Looper.getMainLooper())
    private var worker: Thread? = null
    @Volatile private var session: PyObject? = null
    @Volatile private var stopRequested = false
    /** Connect was requested while the previous session was still shutting down: start once it has. */
    private var pendingConnect = false
    @Volatile private var currentNetwork: Network? = null
    private var lastPhysicalNetwork: Network? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val stateListener: (VpnUiState) -> Unit = { s -> if (worker != null) Notifications.update(this, s) }

    override fun onCreate() {
        super.onCreate()
        VpnStateStore.observe(stateListener)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> startSession()
            ACTION_DISCONNECT -> requestStop()
            // Android's always-on VPN starts the service with the VpnService interface action (at boot, after
            // the process died, or when the user enables it).  Connect if a profile is installed; otherwise
            // report it -- with "Block connections without VPN" Android then keeps all traffic blocked.
            SERVICE_INTERFACE -> {
                Log.i(TAG, "started by Android always-on VPN")
                startSession()
            }
            else -> if (worker == null) stopSelf()   // e.g. a restart by the system: never connect silently
        }
        return START_NOT_STICKY
    }

    // ------------------------------------------------------------------ lifecycle

    private fun startSession() {
        if (worker != null) {
            // Already running.  If it is shutting down, remember the request instead of dropping the tap.
            if (stopRequested) pendingConnect = true
            return
        }
        if (prepare(this) != null) {
            VpnStateStore.update { VpnUiState(Phase.ERROR, message = getString(R.string.permission_needed_service)) }
            stopSelf()
            return
        }
        if (!ProfileStore.hasProfile(this)) {
            VpnStateStore.update { VpnUiState(Phase.ERROR, message = getString(R.string.no_profile_error)) }
            stopSelf()
            return
        }
        stopRequested = false
        pendingConnect = false
        val (alwaysOn, lockdown) = systemVpnMode()
        VpnStateStore.update { VpnUiState(Phase.PREPARING, active = true, alwaysOn = alwaysOn, lockdown = lockdown) }
        try {
            enterForeground()
        } catch (e: Exception) {
            Log.e(TAG, "cannot start the foreground service", e)
            VpnStateStore.update { VpnUiState(Phase.ERROR, message = "Android refused to start the VPN service: ${Redact.text(e.message)}") }
            stopSelf()
            return
        }
        worker = Thread({ runSession() }, "shieldsvpn-session").also { it.start() }
    }

    private fun enterForeground() {
        val n = Notifications.build(this, VpnStateStore.state)
        if (Build.VERSION.SDK_INT >= 34) {
            try {
                startForeground(Notifications.ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } catch (e: RuntimeException) {
                Log.w(TAG, "systemExempted foreground type refused; using specialUse", e)
                startForeground(Notifications.ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            }
        } else {
            startForeground(Notifications.ID, n)
        }
    }

    private fun runSession() {
        var error = ""
        try {
            val module = PythonRuntime.androidClient(applicationContext)
            val secrets = ProfileStore.loadSecrets(this)
            val s = module.callAttr(
                "Session", ProfileStore.profileDir(this).absolutePath, secrets.keyPem, secrets.psk, bridge,
            )
            session = s
            activeSession = s
            if (stopRequested) s.callAttr("stop")
            main.post { registerNetworkCallback() }
            error = s.callAttr("run").toString()
        } catch (e: Throwable) {
            error = Redact.pythonError(e)
            Log.e(TAG, "VPN session failed: $error")
        } finally {
            session = null
            activeSession = null
            main.post { finishSession(error) }
        }
    }

    /** Android's always-on / "Block connections without VPN" settings for this app (API 29+; null = unknown). */
    private fun systemVpnMode(): Pair<Boolean?, Boolean?> =
        if (Build.VERSION.SDK_INT >= 29) isAlwaysOn to isLockdownEnabled else null to null

    private fun requestStop() {
        stopRequested = true
        pendingConnect = false
        if (worker == null) {
            stopSelf()
            return
        }
        VpnStateStore.update { it.copy(phase = Phase.DISCONNECTING) }
        try {
            session?.callAttr("stop")   // thread-safe; if the session does not exist yet, runSession() stops it
        } catch (e: Throwable) {
            Log.w(TAG, "stop failed: ${Redact.pythonError(e)}")
        }
    }

    private fun finishSession(error: String) {
        unregisterNetworkCallback()
        worker = null
        if (pendingConnect) {
            Log.i(TAG, "previous session closed; starting the queued connection")
            startSession()
            return
        }
        VpnStateStore.update { StateMapper.finished(it, error, stopRequested) }
        stopForegroundCompat()
        stopSelf()
    }

    @Suppress("DEPRECATION")
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else stopForeground(true)
    }

    /** The user switched the VPN off in Settings, or another VPN app took over. */
    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by the system")
        requestStop()
    }

    override fun onDestroy() {
        VpnStateStore.remove(stateListener)
        if (worker != null) requestStop()
        unregisterNetworkCallback()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ network changes

    /**
     * Follows the physical network the encrypted UDP flow uses.
     *
     * registerDefaultNetworkCallback() is not usable here: for the app that owns the VPN it follows the VPN
     * network itself (verified on Android 16), so Wi-Fi <-> mobile switches were never reported.  Instead we
     * track the best network that has INTERNET and is NOT a VPN -- the one Android routes our protected
     * socket over -- and ask the session for a new handshake whenever it changes.
     */
    private fun registerNetworkCallback() {
        if (networkCallback != null || worker == null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = onPhysicalNetwork(network)

            override fun onLost(network: Network) {
                if (network == currentNetwork) {
                    currentNetwork = null
                    runCatching { setUnderlyingNetworks(null) }   // "whatever the default is"
                }
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= 31) {
                cm.registerBestMatchingNetworkCallback(request, cb, main)   // listen only
            } else {
                cm.requestNetwork(request, cb, main)   // satisfied by the default network; brings nothing up
            }
            networkCallback = cb
        } catch (e: RuntimeException) {
            Log.w(TAG, "cannot watch network changes", e)
        }
    }

    private fun onPhysicalNetwork(network: Network) {
        if (network == currentNetwork) return
        val previous = lastPhysicalNetwork
        currentNetwork = network
        lastPhysicalNetwork = network
        runCatching { setUnderlyingNetworks(arrayOf(network)) }
        if (previous != null && previous != network) {
            Log.i(TAG, "physical network changed ($previous -> $network); asking for a fresh handshake")
            runCatching { session?.callAttr("network_changed") }
        }
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        lastPhysicalNetwork = null
        runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(cb) }
    }

    // ------------------------------------------------------------------ bridge (Python asyncio thread)

    private val bridge = object : PythonVpnBridge {
        override fun protectSocket(fd: Int): Boolean = protect(fd)

        override fun establishTunnel(settingsJson: String): Int {
            if (stopRequested) return -1
            return try {
                val cfg = TunnelConfig.fromJson(settingsJson)
                val b = Builder()
                    .setSession(cfg.session)
                    .setMtu(cfg.mtu)
                    .setBlocking(false)
                    .setConfigureIntent(
                        PendingIntent.getActivity(
                            this@ShieldsVpnService, 0, Intent(this@ShieldsVpnService, MainActivity::class.java),
                            PendingIntent.FLAG_IMMUTABLE,
                        ),
                    )
                cfg.addresses.forEach { b.addAddress(it.address, it.prefix) }
                cfg.routes.forEach { b.addRoute(it.address, it.prefix) }
                cfg.dns.forEach { b.addDnsServer(it) }
                // A family without a tunnel address: in split-tunnel mode let it use the normal network;
                // in full-tunnel mode leave it un-allowed, which makes Android block it (no IPv6 leak).
                if ("ipv4" in cfg.bypassFamilies) b.allowFamily(OsConstants.AF_INET)
                if ("ipv6" in cfg.bypassFamilies) b.allowFamily(OsConstants.AF_INET6)
                // The app's own sockets (the encrypted UDP flow, DNS for the server name) bypass the tunnel.
                b.addDisallowedApplication(packageName)
                if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
                currentNetwork?.let { b.setUnderlyingNetworks(arrayOf(it)) }
                val pfd = b.establish() ?: return -1   // null: consent revoked in the meantime
                // isAlwaysOn()/isLockdownEnabled() are only reliable once the VPN interface exists (verified on
                // Android 16: both read false before establish() even with lockdown on), so report them now.
                val (alwaysOn, lockdown) = systemVpnMode()
                VpnStateStore.update { it.copy(alwaysOn = alwaysOn, lockdown = lockdown) }
                Log.i(TAG, "tunnel established: ${cfg.addresses.joinToString()} routes ${cfg.routes.joinToString()}" +
                    " dns ${cfg.dns.joinToString()} mtu ${cfg.mtu}${if (cfg.fullTunnel) " (full tunnel)" else ""}")
                pfd.detachFd()   // Python owns and closes the descriptor from here on
            } catch (e: Exception) {
                Log.e(TAG, "cannot establish the VPN interface: ${Redact.text(e.message)}")
                -1
            }
        }

        override fun onState(state: String, infoJson: String) {
            val info = runCatching { JSONObject(infoJson) }.getOrDefault(JSONObject())
            if (state == "error") Log.w(TAG, "session error: ${Redact.text(info.optString("message"))}")
            else Log.i(TAG, "session state: $state")
            if (stopRequested && state != "disconnected") return  // keep showing "Disconnecting"
            VpnStateStore.update { StateMapper.fromPython(it, state, info, SystemClock.elapsedRealtime()) }
        }
    }
}
