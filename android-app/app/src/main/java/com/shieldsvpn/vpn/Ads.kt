package com.shieldsvpn.vpn

import android.app.Activity
import android.util.Log
import com.google.android.gms.ads.AdError
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.FullScreenContentCallback
import com.google.android.gms.ads.LoadAdError
import com.google.android.gms.ads.MobileAds
import com.google.android.gms.ads.interstitial.InterstitialAd
import com.google.android.gms.ads.interstitial.InterstitialAdLoadCallback
import com.google.android.gms.ads.rewarded.RewardedAd
import com.google.android.gms.ads.rewarded.RewardedAdLoadCallback
import com.google.android.gms.ads.rewarded.ServerSideVerificationOptions
import com.google.android.ump.ConsentRequestParameters
import com.google.android.ump.UserMessagingPlatform

/**
 * Free-plan ads (Google AdMob), used only when the portal turns them on.
 *
 *  - Consent first: Google's User Messaging Platform shows the consent form where the law requires it
 *    (GDPR/UK, US states); ads are requested only once `canRequestAds()` allows it.
 *  - Rewarded video = free VPN time.  The portal's one-time nonce goes into the ad's server-side verification
 *    data, so Google's signed callback to the portal (pqvpn/portal/rewards.py) is what grants the time; the app
 *    cannot grant time to itself.
 *  - An interstitial is shown after a Free device connects.
 *
 * The app's own traffic is excluded from the VPN (addDisallowedApplication), so ads load outside the tunnel.
 * All calls on the main thread.
 */
object Ads {
    private const val TAG = "ShieldsAds"
    private var started = false

    /** Ask for consent if needed, then start the SDK; [ready] gets whether ads may be requested. */
    fun prepare(activity: Activity, ready: (Boolean) -> Unit) {
        val consent = UserMessagingPlatform.getConsentInformation(activity)
        val start = {
            val ok = consent.canRequestAds()
            if (ok && !started) {
                started = true
                MobileAds.initialize(activity.applicationContext) {}
            }
            ready(ok)
        }
        consent.requestConsentInfoUpdate(activity, ConsentRequestParameters.Builder().build(), {
            UserMessagingPlatform.loadAndShowConsentFormIfRequired(activity) { formError ->
                if (formError != null) Log.w(TAG, "consent form: ${formError.message}")
                start()
            }
        }, { error ->
            Log.w(TAG, "consent info: ${error.message}")
            start()   // canRequestAds() still reflects any consent given earlier
        })
    }

    /**
     * Shows one rewarded video.  [done] gets (earned, error): earned = the user watched to the end, so the
     * portal should receive Google's callback for [nonce] within seconds.
     */
    fun showRewarded(activity: Activity, nonce: String, deviceName: String, done: (Boolean, String?) -> Unit) {
        prepare(activity) { allowed ->
            if (!allowed) {
                done(false, "Ads cannot be shown until you answer the consent question.")
                return@prepare
            }
            RewardedAd.load(activity, BuildConfig.ADMOB_REWARDED_ID, AdRequest.Builder().build(),
                object : RewardedAdLoadCallback() {
                    override fun onAdLoaded(ad: RewardedAd) {
                        var earned = false
                        ad.setServerSideVerificationOptions(
                            ServerSideVerificationOptions.Builder().setCustomData(nonce).setUserId(deviceName).build(),
                        )
                        ad.fullScreenContentCallback = object : FullScreenContentCallback() {
                            override fun onAdDismissedFullScreenContent() = done(earned, null)
                            override fun onAdFailedToShowFullScreenContent(e: AdError) =
                                done(false, "The ad could not be shown (${e.message}).")
                        }
                        ad.show(activity) { earned = true }
                    }

                    override fun onAdFailedToLoad(e: LoadAdError) =
                        done(false, "No ad is available right now (${e.message}). Try again in a minute.")
                })
        }
    }

    /** Best effort: an interstitial after a Free device connected.  Failures are only logged. */
    fun showInterstitial(activity: Activity) {
        prepare(activity) { allowed ->
            if (!allowed) return@prepare
            InterstitialAd.load(activity, BuildConfig.ADMOB_INTERSTITIAL_ID, AdRequest.Builder().build(),
                object : InterstitialAdLoadCallback() {
                    override fun onAdLoaded(ad: InterstitialAd) {
                        if (!activity.isFinishing && !activity.isDestroyed) ad.show(activity)
                    }

                    override fun onAdFailedToLoad(e: LoadAdError) {
                        Log.i(TAG, "no interstitial: ${e.message}")
                    }
                })
        }
    }
}
