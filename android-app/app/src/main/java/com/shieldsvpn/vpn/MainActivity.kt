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
import androidx.activity.OnBackPressedCallback
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
import com.android.billingclient.api.Purchase
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
    /** Free / Pro status from the portal (null = not known yet, or this build has no portal). */
    private var account: AccountInfo? = null
    private var accountBusy = false
    /**
     * A certificate renewal is queued or running.  /me answers fetched before it finishes still say "renew"; without
     * this guard each of them queued another renewal, which the portal refuses (409 not_due) once the first is done.
     */
    private var renewing = false
    /** Registration with the portal is running, and whether the user tapped Connect meanwhile. */
    private var enrolling = false
    private var connectAfterEnroll = false
    /** connectedSince of the session we already showed the "connected" interstitial for. */
    private var adShownFor = 0L
    /** The user just watched a rewarded ad to connect: no second (interstitial) ad for that connection. */
    private var skipNextInterstitial = false
    /** This installation accepted the User Agreement (Terms.kt); until then nothing registers or connects. */
    private var termsAccepted = false
    /** Google Play Billing (Play Store build only), and the subscription's plans with Google's prices. */
    private var billing: PlayBilling? = null
    private var playPlans: List<PlayPlan> = emptyList()
    private var playLoadedFor = ""
    private var playRestored = false

    /** The user tapped Disconnect on a Free plan that shows an ad then; shown once the tunnel is down. */
    private var adAfterDisconnect = false
    /** When the last connect/disconnect interstitial was shown (SystemClock.elapsedRealtime), for the admin's gap. */
    private var lastToggleAd = 0L
    private var lastPhase: Phase? = null

    private val stateListener: (VpnUiState) -> Unit = { s ->
        pushState(s)
        val a = account
        if (s.phase == Phase.CONNECTED && s.connectedSince != adShownFor && accountAvailable && a != null &&
            a.toggleAd(connect = true)
        ) {
            adShownFor = s.connectedSince
            if (skipNextInterstitial) skipNextInterstitial = false else showToggleAd(a)
        }
        if (s.phase == Phase.DISCONNECTED && !s.active && lastPhase != null && lastPhase != Phase.DISCONNECTED) {
            if (adAfterDisconnect && a != null) showToggleAd(a)
            adAfterDisconnect = false
            if (accountAvailable && termsAccepted) refreshAccount()   // the balance stopped going down
        }
        lastPhase = s.phase
    }

    /** One interstitial for a tap on Connect or Disconnect, unless the last one was within the admin's gap. */
    private fun showToggleAd(a: AccountInfo) {
        val now = SystemClock.elapsedRealtime()
        if (lastToggleAd != 0L && now - lastToggleAd < a.toggleAdGap * 1000L) return
        lastToggleAd = now
        Ads.showInterstitial(this)
    }

    /** While the UI has a menu or sheet open, Back closes that instead of leaving the app. */
    private val backToUi = object : OnBackPressedCallback(false) {
        override fun handleOnBackPressed() = send(UiJson.back())
    }

    /** This build talks to a portal and the installed profile is the app's own registration. */
    private val accountAvailable: Boolean get() = Portal.configured && profile?.enrolled == true

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
        termsAccepted = Terms.accepted(this)
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            showWebViewTooOld()
            return
        }
        val view = createWebView()
        web = view
        setContentView(view)
        onBackPressedDispatcher.addCallback(this, backToUi)
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
        if (termsAccepted && accountAvailable && uiReady) refreshAccount()   // e.g. back from the payment page
    }

    override fun onStop() {
        VpnStateStore.remove(stateListener)
        main.removeCallbacks(trafficTick)
        super.onStop()
    }

    override fun onDestroy() {
        billing?.end()
        billing = null
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

    private fun pushAccount() =
        send(UiJson.account(accountAvailable, shown(account), accountBusy, System.currentTimeMillis(), Portal.configured,
            imports = !BuildConfig.PLAY_STORE, privacy = BuildConfig.PRIVACY_URL.isNotBlank()))

    /** What the plan card shows: in the Play Store build, Google's plans and prices replace the portal's (Paddle). */
    private fun shown(a: AccountInfo?): AccountInfo? = if (!BuildConfig.PLAY_STORE || a == null) a else
        a.copy(payments = a.play && playPlans.isNotEmpty(), prices = PlayPlans.options(playPlans), priceLabel = "")

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

    // Never log `raw`: sign-in commands carry the password the user typed.
    private fun onUiMessage(raw: String?) {
        val command = UiJson.command(raw)
        if (!termsAccepted && command != null && command !in UiJson.BEFORE_TERMS) {
            Log.i(TAG, "ignored \"$command\": the User Agreement is not accepted yet")
            return
        }
        when (command) {
            "ready" -> {
                backToUi.isEnabled = false   // a reloaded page has no overlay open
                send(insets)
                send(UiJson.terms(termsAccepted, Terms.VERSION))
                pushState()
                pushAccount()
                if (termsAccepted) startAccount()
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
                if (VpnStateStore.state.active) {
                    adAfterDisconnect = accountAvailable && account?.toggleAd(connect = false) == true
                    ShieldsVpnService.disconnect(this)
                }
            }
            "importProfile" -> if (!BuildConfig.PLAY_STORE) chooseProfile()   // Play build: registration only
            "removeProfile" -> removeProfile()
            "openPortal" -> openPortal()
            "openVpnSettings" -> openVpnSettings()
            "refreshAccount" -> if (accountAvailable) refreshAccount()
            "watchAd" -> watchAd()
            "signIn" -> accountCall("signIn", "/api/v1/login", JSONObject()
                .put("login", UiJson.field(raw, "login")).put("password", UiJson.field(raw, "password", 128))
                .put("code", UiJson.field(raw, "code", 16)))
            "signUp" -> accountCall("signUp", "/api/v1/signup", JSONObject()
                .put("email", UiJson.field(raw, "email")).put("password", UiJson.field(raw, "password", 128)))
            "verifyEmail" -> accountCall("verifyEmail", "/api/v1/signup/verify", JSONObject()
                .put("email", UiJson.field(raw, "email")).put("code", UiJson.field(raw, "code", 16)))
            "forgotPassword" -> accountCall("forgotPassword", "/api/v1/forgot", JSONObject()
                .put("login", UiJson.field(raw, "login")))
            "resetPassword" -> accountCall("resetPassword", "/api/v1/forgot/verify", JSONObject()
                .put("login", UiJson.field(raw, "login")).put("code", UiJson.field(raw, "code", 16))
                .put("password", UiJson.field(raw, "password", 128)))
            "signOut" -> accountCall("signOut", "/api/v1/logout", JSONObject())
            "goPro" -> goPro(UiJson.field(raw, "period", 8))
            "manageSubscription" -> manageSubscription()
            "deleteAccount" -> accountCall("deleteAccount", "/api/v1/account/delete", JSONObject()
                .put("password", UiJson.field(raw, "password", 128)).put("code", UiJson.field(raw, "code", 16)))
            "openPrivacy" -> BuildConfig.PRIVACY_URL.takeIf { it.startsWith("https://") }
                ?.let { openUrl(it, getString(R.string.privacy_policy)) }
            "overlay" -> backToUi.isEnabled = UiJson.flag(raw, "open")
            "acceptTerms" -> if (!termsAccepted && UiJson.field(raw, "version", 32) == Terms.VERSION) {
                Terms.accept(this)
                termsAccepted = true
                send(UiJson.terms(true, Terms.VERSION))
                startAccount()
            }
            "declineTerms" -> finishAndRemoveTask()   // asked again the next time the app opens
            else -> Log.w(TAG, "ignored an unknown message from the UI")
        }
    }

    /** After the agreement: refresh the plan, or register this phone on its first start (portal builds). */
    private fun startAccount() {
        if (accountAvailable) refreshAccount()
        else if (Portal.configured && profile == null && !importing) enroll(connectAfter = false)
    }

    // ------------------------------------------------------------------ Free with ads / sign-in / Pro

    /**
     * A portal build registers this phone (no account; Free plan): by itself when the app first opens, and again on
     * Connect if that did not work.  A tap on Connect while the registration runs connects as soon as it is done.
     */
    private fun enroll(connectAfter: Boolean) {
        if (connectAfter) connectAfterEnroll = true
        if (enrolling) return
        enrolling = true
        accountBusy = true
        pushAccount()
        io.execute {
            val outcome = runCatching { Portal.enroll(applicationContext) }
            main.post {
                enrolling = false
                accountBusy = false
                val connect = connectAfterEnroll
                connectAfterEnroll = false
                outcome.onSuccess { (summary, me) ->
                    profile = summary
                    if (me != null) updateAccount(me)
                    pushState()
                    if (connect) onConnect()
                }.onFailure { e ->
                    val msg = if (e is PortalException) e.message ?: "" else Redact.pythonError(e)
                    Log.w(TAG, "registration failed: ${Redact.text(msg)}")
                    // Opening the app offline is normal: only a tap on Connect deserves an error dialog.
                    if (connect) notice(false, getString(R.string.register_failed), msg)
                }
                pushAccount()
            }
        }
    }

    private fun refreshAccount() {
        io.execute {
            val outcome = runCatching { Portal.call(applicationContext, "GET", "/api/v1/me") }
            main.post {
                outcome.onSuccess { updateAccount(it) }
                    .onFailure { Log.i(TAG, "account status unavailable: ${Redact.text(it.message)}") }
            }
        }
    }

    private fun updateAccount(me: JSONObject) {
        // The server may still see a session that this phone has just closed: when the VPN is off here, the
        // balance is not being used, whatever the answer says.
        val a = AccountInfo.fromMe(me, System.currentTimeMillis() / 1000)
            .let { if (VpnStateStore.state.active) it else it.copy(freeCounting = false) }
        account = a
        pushAccount()
        if (VpnStateStore.state.active) ShieldsVpnService.updateFreeTime(this, a.stopAtMs(System.currentTimeMillis()))
        if (a.renewCertificate && !VpnStateStore.state.active && !renewing) renewCertificate()
        if (BuildConfig.PLAY_STORE && a.play) startPlay(a)
    }

    // ------------------------------------------------------------------ Google Play Billing (Play Store build)

    /** Loads the Play plans once per product and, once signed in, re-sends Google's purchases to the portal. */
    private fun startPlay(a: AccountInfo) {
        val b = billing ?: PlayBilling(this) { purchases -> main.post { onPlayPurchases(purchases, notify = true) } }
            .also { billing = it }
        if (playLoadedFor != a.playProduct) {
            playLoadedFor = a.playProduct
            b.loadPlans(a.playProduct) { plans -> main.post { playPlans = plans; pushAccount() } }
        }
        if (a.signedIn && a.playAccount.isNotEmpty() && !playRestored) {
            playRestored = true
            b.restore { purchases -> main.post { onPlayPurchases(purchases, notify = false) } }
        }
    }

    private fun onPlayPurchases(purchases: List<Purchase>, notify: Boolean) {
        val product = account?.playProduct ?: return
        for (p in purchases.filter { product in it.products }) {
            when (p.purchaseState) {
                Purchase.PurchaseState.PURCHASED -> verifyPlay(product, p.purchaseToken, notify)
                Purchase.PurchaseState.PENDING -> if (notify) {
                    notice(false, getString(R.string.go_pro), getString(R.string.play_pending))
                }
                else -> {}
            }
        }
    }

    /** The portal checks the purchase with Google, acknowledges it and turns Pro on (pqvpn/portal/play.py). */
    private fun verifyPlay(product: String, token: String, notify: Boolean) {
        io.execute {
            val outcome = runCatching {
                Portal.call(applicationContext, "POST", "/api/v1/play/verify",
                    JSONObject().put("product_id", product).put("purchase_token", token))
            }
            main.post {
                outcome.onSuccess { me ->
                    updateAccount(me)
                    if (notify && account?.pro == true) notice(true, getString(R.string.go_pro), getString(R.string.play_done))
                }.onFailure { e ->
                    Log.w(TAG, "Play purchase check failed: ${Redact.text(e.message)}")
                    if (notify) notice(false, getString(R.string.go_pro), e.message ?: Redact.pythonError(e))
                }
            }
        }
    }

    private fun manageSubscription() {
        val a = account ?: return
        if (BuildConfig.PLAY_STORE) {
            // Google Play's own subscription page: cancel, change plan, payment method.
            openUrl("https://play.google.com/store/account/subscriptions?sku=${Uri.encode(a.playProduct)}" +
                "&package=${Uri.encode(packageName)}", getString(R.string.go_pro))
        } else {
            openFromPortal("manageSubscription", "/api/v1/manage")
        }
    }

    private fun renewCertificate() {
        renewing = true
        io.execute {
            val outcome = runCatching { Portal.renew(applicationContext) }
            main.post {
                renewing = false   // a failure (e.g. offline) is retried at the next /me answer that says "renew"
                outcome.onSuccess { profile = it; pushState() }
                    .onFailure { Log.w(TAG, "certificate renewal failed: ${Redact.text(it.message)}") }
            }
        }
    }

    /** A sign-in / sign-up / reset step.  Answers that are a device status (`/me` shape) update the plan card. */
    private fun accountCall(op: String, path: String, body: JSONObject) {
        if (!accountAvailable) return
        accountBusy = true
        pushAccount()
        io.execute {
            val outcome = runCatching { Portal.call(applicationContext, "POST", path, body) }
            main.post {
                accountBusy = false
                outcome.onSuccess { data ->
                    if (op == "deleteAccount" || op == "signOut") playRestored = false
                    if (data.has("plan")) updateAccount(data) else pushAccount()
                    send(UiJson.accountResult(op, true))
                }.onFailure { e ->
                    pushAccount()
                    val code = (e as? PortalException)?.code ?: "error"
                    send(UiJson.accountResult(op, false, code, e.message ?: Redact.pythonError(e)))
                }
            }
        }
    }

    /**
     * Free time: one rewarded video.  Google's signed callback to the portal grants the time (see Ads).
     * [connectAfter]: the user tapped Connect with no time left; connect as soon as the time is granted.
     */
    private fun watchAd(connectAfter: Boolean = false) {
        val a = account
        val name = profile?.account ?: return
        if (!accountAvailable || a == null || accountBusy) return
        if (!a.admob) {
            notice(false, getString(R.string.free_time_title), "Free time from ads is not available right now.")
            return
        }
        if (VpnStateStore.state.active) {   // the server refuses it too: time is added while disconnected
            notice(false, getString(R.string.free_time_title), getString(R.string.ad_disconnect_first))
            return
        }
        val wait = a.nextRewardSeconds(System.currentTimeMillis() / 1000)
        if (wait > 0) {   // the button shows the countdown; a tap that slips through just explains it
            notice(false, getString(R.string.free_time_title), getString(R.string.next_ad_in, wait))
            return
        }
        accountBusy = true
        pushAccount()
        io.execute {
            val start = runCatching {
                Portal.call(applicationContext, "POST", "/api/v1/reward/start", JSONObject().put("kind", "admob"))
            }
            main.post {
                start.onFailure { e ->
                    accountBusy = false
                    pushAccount()
                    // Right after Disconnect the server can still be seeing the last packets for a few seconds.
                    val text = if ((e as? PortalException)?.code == "connected" && !VpnStateStore.state.active)
                        getString(R.string.ad_still_closing) else e.message ?: Redact.pythonError(e)
                    notice(false, getString(R.string.free_time_title), text)
                }.onSuccess { r ->
                    val nonce = r.getString("nonce")
                    Ads.showRewarded(this, nonce, name) { earned, error ->
                        if (!earned) {
                            accountBusy = false
                            pushAccount()
                            notice(false, getString(R.string.free_time_title),
                                error ?: "Watch the whole ad to get free time.")
                        } else {
                            collectReward(nonce, a.freeSeconds, a.admobVerified, connectAfter)
                        }
                    }
                }
            }
        }
    }

    /** After a watched ad: test mode claims directly; normally wait for Google's callback to reach the portal. */
    private fun collectReward(nonce: String, before: Long, verified: Boolean, connectAfter: Boolean) {
        io.execute {
            var me: JSONObject? = null
            if (!verified) {
                me = runCatching {
                    Portal.call(applicationContext, "POST", "/api/v1/reward/claim", JSONObject().put("nonce", nonce))
                }.getOrNull()
            } else {
                for (attempt in 0 until 10) {   // Google usually calls back within a few seconds
                    Thread.sleep(2000)
                    val m = runCatching { Portal.call(applicationContext, "GET", "/api/v1/me") }.getOrNull()
                    if (m != null && AccountInfo.balance(m) > before) {
                        me = m
                        break
                    }
                }
            }
            main.post {
                accountBusy = false
                if (me != null) {
                    updateAccount(me)
                    if (connectAfter && account?.let { it.pro || it.freeSecondsLeft(System.currentTimeMillis() / 1000) > 0 } == true) {
                        skipNextInterstitial = true   // they just watched an ad for this connection
                        onConnect()
                    } else {
                        // A toast, not a dialog: the next ad's countdown stays in view to build up more time.
                        val minutes = account?.freeMinutes ?: 30
                        notice(true, getString(R.string.free_time_title),
                            resources.getQuantityString(R.plurals.free_time_added, minutes, minutes))
                    }
                } else {
                    pushAccount()
                    notice(false, getString(R.string.free_time_title), getString(R.string.ad_not_confirmed))
                    refreshAccount()
                }
            }
        }
    }

    /** [period] is the Pro plan the user tapped ("week", "month", "year"); "" = the portal's default plan. */
    private fun goPro(period: String) {
        val a = account ?: return
        when {
            !accountAvailable -> return
            !a.accounts -> notice(false, getString(R.string.go_pro), "Pro is not available yet.")
            !a.signedIn -> send(UiJson.accountResult("goPro", false, "sign_in_required",
                "Pro is tied to your account: sign in or create one first."))
            BuildConfig.PLAY_STORE -> {
                // Play's payments policy: Pro is sold only through Google Play Billing in this build.
                val plan = playPlans.firstOrNull { it.period == period } ?: playPlans.firstOrNull()
                val b = billing
                if (!a.play || a.playAccount.isEmpty() || plan == null || b == null || !b.buy(this, plan, a.playAccount)) {
                    notice(false, getString(R.string.go_pro), "Google Play purchases are not available right now.")
                }
            }
            !a.payments -> notice(false, getString(R.string.go_pro), "Payments are not available yet.")
            // Only a plan the portal offered goes out; the portal checks it again anyway.
            else -> openFromPortal("goPro", "/api/v1/checkout",
                if (a.prices.any { it.period == period }) JSONObject().put("period", period) else JSONObject())
        }
    }

    /** Asks the portal for a one-time link (checkout, subscription management) and opens it in the browser. */
    private fun openFromPortal(op: String, path: String, body: JSONObject = JSONObject()) {
        if (!accountAvailable || accountBusy) return
        accountBusy = true
        pushAccount()
        io.execute {
            val outcome = runCatching { Portal.call(applicationContext, "POST", path, body) }
            main.post {
                accountBusy = false
                pushAccount()
                outcome.onSuccess { data ->
                    val url = data.optString("url")
                    if (url.startsWith("https://") || (BuildConfig.PORTAL_ALLOW_HTTP && url.startsWith("http://"))) {
                        openUrl(url, getString(R.string.go_pro))
                    }
                    send(UiJson.accountResult(op, true))
                }.onFailure { e ->
                    send(UiJson.accountResult(op, false, (e as? PortalException)?.code ?: "error",
                        e.message ?: Redact.pythonError(e)))
                }
            }
        }
    }

    private fun openUrl(url: String, title: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (e: ActivityNotFoundException) {
            notice(false, title, getString(R.string.no_browser))
        }
    }

    private fun refreshPermission() {
        permissionNeeded = VpnService.prepare(this) != null
        pushState()
    }

    private fun onConnect() {
        val s = VpnStateStore.state
        val a = account
        when {
            s.active || s.phase == Phase.DISCONNECTING -> return
            profile == null -> if (Portal.configured) enroll(connectAfter = true) else chooseProfile()
            // Free with no time left: the server would refuse the handshake.  The screen said "a short ad gives you
            // free minutes", so the tap plays it and connects afterwards; without ads left, explain instead.
            accountAvailable && a != null && !a.pro && a.freeSecondsLeft(System.currentTimeMillis() / 1000) <= 0 ->
                if (a.adBeforeConnect(System.currentTimeMillis() / 1000)) watchAd(connectAfter = true)
                else notice(false, getString(R.string.free_time_title), getString(R.string.no_free_time, a.freeMinutes))
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
        val a = account
        ShieldsVpnService.connect(this, if (accountAvailable && a != null) a.stopAtMs(System.currentTimeMillis()) else 0L)
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
                account = null
                pushAccount()
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
        openUrl(url, getString(R.string.open_portal))
    }
}
