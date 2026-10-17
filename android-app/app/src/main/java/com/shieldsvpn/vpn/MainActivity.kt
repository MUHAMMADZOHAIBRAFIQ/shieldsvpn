package com.shieldsvpn.vpn

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.webkit.ConsoleMessage
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.widget.TextView
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors

/**
 * Hosts the React UI (android-app/ui) in a WebView and connects it to the VPN service.
 *
 * Security of the WebView:
 *  - the UI is served from the APK's assets by WebViewAssetLoader at https://appassets.androidplatform.net;
 *    every other URL gets an empty 404, and navigation away from the page is blocked;
 *  - no file or content access, no zoom, no new windows, no mixed content, and the page's own CSP forbids
 *    inline scripts and all network connections;
 *  - the bridge object (window.ShieldsBridge) is injected only for that origin and only into the main
 *    frame; messages are plain JSON commands from a fixed list (UiJson.COMMANDS).
 */
class MainActivity : AppCompatActivity() {
    companion object {
        private const val TAG = "ShieldsUi"
        private const val ORIGIN = "https://appassets.androidplatform.net"
        private const val START_URL = "$ORIGIN/assets/ui/index.html"
    }

    private var web: WebView? = null
    private var port: JavaScriptReplyProxy? = null
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var profile: ProfileSummary? = null
    private var importing = false
    private var permissionNeeded = false
    private var askedForNotifications = false
    private var insets: JSONObject = UiJson.insets(0f, 0f, 0f, 0f)
    @Volatile private var uiReady = false

    private val stateListener: (VpnUiState) -> Unit = { pushState(it) }

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpn()
        } else {
            VpnStateStore.update { VpnUiState(Phase.ERROR, message = getString(R.string.permission_declined)) }
        }
        refreshPermission()
    }

    private val pickProfile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) importProfile(uri)
    }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { requestVpnThenConnect() }

    // ------------------------------------------------------------------ lifecycle

    override fun onCreate(savedInstanceState: Bundle?) {
        // Keep the splash until the page has rendered (first WebView start can take a few seconds on slow
        // devices); never longer than 10 s, so a broken page cannot hide the app behind the splash.
        val created = SystemClock.elapsedRealtime()
        installSplashScreen().setKeepOnScreenCondition {
            !uiReady && SystemClock.elapsedRealtime() - created < 10_000
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)
        profile = ProfileStore.summary(this)
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            showWebViewTooOld()
            return
        }
        val view = createWebView()
        web = view
        setContentView(view)
        // The page draws behind the system bars; tell it how much space they take (in CSS px = dp).
        ViewCompat.setOnApplyWindowInsetsListener(view) { _, ins ->
            val b = ins.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val d = resources.displayMetrics.density
            insets = UiJson.insets(b.top / d, b.bottom / d, b.left / d, b.right / d)
            send(insets)
            ins
        }
        view.loadUrl(START_URL)
    }

    override fun onStart() {
        super.onStart()
        VpnStateStore.observe(stateListener)
        main.post(trafficTick)
    }

    override fun onResume() {
        super.onResume()
        refreshPermission()   // consent can be revoked in Settings while we are in the background
    }

    override fun onStop() {
        VpnStateStore.remove(stateListener)
        main.removeCallbacks(trafficTick)
        super.onStop()
    }

    override fun onDestroy() {
        io.shutdown()
        port = null
        web?.destroy()
        web = null
        super.onDestroy()
    }

    // ------------------------------------------------------------------ WebView

    @SuppressLint("SetJavaScriptEnabled")   // our own bundled React app, served only from the APK
    private fun createWebView(): WebView {
        val view = WebView(this)
        view.setBackgroundColor(ContextCompat.getColor(this, R.color.bg))
        view.isVerticalScrollBarEnabled = false
        view.overScrollMode = View.OVER_SCROLL_NEVER
        with(view.settings) {
            javaScriptEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            domStorageEnabled = false
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
            setSupportZoom(false)
            builtInZoomControls = false
            displayZoomControls = false
            setGeolocationEnabled(false)
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        }
        val assets = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
        view.webViewClient = object : WebViewClientCompat() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse =
                assets.shouldInterceptRequest(request.url)
                    ?: WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0)))

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true

            @RequiresApi(26)
            override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                Log.w(TAG, "WebView renderer gone (crashed=${detail.didCrash()}); recreating the screen")
                recreate()
                return true   // the VPN keeps running in its service; only the screen is rebuilt
            }
        }
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)   // chrome://inspect for debug builds only
            view.webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(m: ConsoleMessage): Boolean {
                    Log.d(TAG, "console: ${Redact.text(m.message())} (${m.sourceId()}:${m.lineNumber()})")
                    return true
                }
            }
        }
        WebViewCompat.addWebMessageListener(view, "ShieldsBridge", setOf(ORIGIN)) { _, message, origin, isMainFrame, reply ->
            if (!isMainFrame || origin.toString().trimEnd('/') != ORIGIN) return@addWebMessageListener
            port = reply
            onUiMessage(message.data)
        }
        return view
    }

    private fun showWebViewTooOld() {
        setContentView(TextView(this).apply {
            text = "ShieldsVPN needs a newer Android System WebView. Update \"Android System WebView\" " +
                "(or Chrome) from the Play Store and open the app again."
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.ink))
            setBackgroundColor(ContextCompat.getColor(this@MainActivity, R.color.bg))
            gravity = Gravity.CENTER
            setPadding(64, 64, 64, 64)
        })
    }

    private fun send(message: JSONObject) {
        val p = port ?: return
        try {
            p.postMessage(message.toString())
        } catch (e: IllegalStateException) {
            Log.w(TAG, "UI not ready: ${e.message}")
        }
    }

    private fun pushState(s: VpnUiState = VpnStateStore.state) {
        send(UiJson.state(s, profile, importing, permissionNeeded, System.currentTimeMillis(), SystemClock.elapsedRealtime()))
    }

    private fun notice(ok: Boolean, title: String, text: String) = send(UiJson.notice(ok, title, text))

    private val trafficTick = object : Runnable {
        override fun run() {
            if (VpnStateStore.state.active && port != null) {
                io.execute {
                    val json = ShieldsVpnService.trafficJson()
                    main.post { UiJson.traffic(json, System.currentTimeMillis())?.let(::send) }
                }
            }
            main.postDelayed(this, 1000)
        }
    }

    // ------------------------------------------------------------------ commands from the UI

    private fun onUiMessage(raw: String?) {
        when (UiJson.command(raw)) {
            "ready" -> {
                send(insets)
                pushState()
                // React has rendered into the DOM.  Lift the splash only once WebView says a frame with that
                // content is ready to draw (VisualStateCallback), so the user never sees an empty window
                // while the WebView's first frame is still being composited.
                val v = web
                if (v != null && WebViewFeature.isFeatureSupported(WebViewFeature.VISUAL_STATE_CALLBACK)) {
                    WebViewCompat.postVisualStateCallback(v, SystemClock.uptimeMillis()) { uiReady = true }
                } else {
                    uiReady = true
                }
            }
            "connect" -> {
                web?.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
                onConnect()
            }
            "disconnect" -> {
                web?.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
                if (VpnStateStore.state.active) ShieldsVpnService.disconnect(this)
            }
            "importProfile" -> chooseProfile()
            "removeProfile" -> removeProfile()
            "openPortal" -> openPortal()
            "openVpnSettings" -> openVpnSettings()
            else -> Log.w(TAG, "ignored an unknown message from the UI")
        }
    }

    private fun refreshPermission() {
        permissionNeeded = VpnService.prepare(this) != null
        pushState()
    }

    private fun onConnect() {
        val s = VpnStateStore.state
        when {
            s.active || s.phase == Phase.DISCONNECTING -> return
            profile == null -> chooseProfile()
            Build.VERSION.SDK_INT >= 33 && !askedForNotifications &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED -> {
                askedForNotifications = true
                notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)  // then requestVpnThenConnect()
            }
            else -> requestVpnThenConnect()
        }
    }

    private fun requestVpnThenConnect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            VpnStateStore.update { VpnUiState(Phase.PREPARING, message = getString(R.string.sub_waiting_permission)) }
            vpnConsent.launch(consent)   // Android's own VPN permission dialog
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        VpnStateStore.update { VpnUiState(Phase.PREPARING, active = true) }
        ShieldsVpnService.connect(this)
    }

    private fun chooseProfile() {
        if (VpnStateStore.state.active || importing) {
            notice(false, getString(R.string.import_profile), getString(R.string.disconnect_first))
            return
        }
        pickProfile.launch(arrayOf("application/zip", "application/x-zip-compressed", "application/octet-stream"))
    }

    private fun importProfile(uri: Uri) {
        importing = true
        pushState()
        io.execute {
            val outcome: Result<ProfileSummary> = runCatching { ProfileStore.importProfile(applicationContext, uri) }
            main.post {
                importing = false
                outcome.onSuccess {
                    profile = it
                    VpnStateStore.update { VpnUiState() }
                    notice(true, getString(R.string.import_profile), getString(R.string.import_ok, it.account))
                }.onFailure { e ->
                    val msg = if (e is ProfileImportException) e.message ?: "" else Redact.pythonError(e)
                    Log.w(TAG, "profile import failed: ${Redact.text(msg)}")
                    notice(false, getString(R.string.import_failed_title), msg)
                }
                pushState()
            }
        }
    }

    private fun removeProfile() {
        if (VpnStateStore.state.active) {
            notice(false, getString(R.string.remove_profile), getString(R.string.disconnect_first))
            return
        }
        io.execute {
            ProfileStore.remove(applicationContext)
            main.post {
                profile = null
                VpnStateStore.update { VpnUiState() }
                notice(true, getString(R.string.remove_profile), getString(R.string.profile_removed))
            }
        }
    }

    /** Android's own VPN settings: where the user turns on always-on VPN and "Block connections without VPN". */
    private fun openVpnSettings() {
        try {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        } catch (e: ActivityNotFoundException) {
            notice(false, getString(R.string.vpn_settings), getString(R.string.no_vpn_settings))
        }
    }

    private fun openPortal() {
        val url = profile?.portalUrl?.takeIf { it.startsWith("https://") || it.startsWith("http://") } ?: return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (e: ActivityNotFoundException) {
            notice(false, getString(R.string.open_portal), getString(R.string.no_browser))
        }
    }
}
