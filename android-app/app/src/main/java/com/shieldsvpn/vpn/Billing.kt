package com.shieldsvpn.vpn

import android.app.Activity
import android.content.Context
import android.util.Log
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.PendingPurchasesParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.PurchasesUpdatedListener
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams

/** One base plan of the Pro subscription in Google Play.  [label] carries Google's price for the user's country. */
data class PlayPlan(val period: String, val label: String, val offerToken: String)

/** Pure helpers for the Play plans, unit-tested on the JVM. */
object PlayPlans {
    val ORDER = listOf("week", "month", "year")
    private val NAMES = mapOf("week" to "Weekly", "month" to "Monthly", "year" to "Yearly")

    /** ISO 8601 billing period of a base plan ("P1W", "P1M", "P1Y") -> "week" / "month" / "year"; others: null. */
    fun period(billingPeriod: String): String? = when (billingPeriod) {
        "P1W", "P7D" -> "week"
        "P1M" -> "month"
        "P1Y", "P12M" -> "year"
        else -> null
    }

    fun label(formattedPrice: String, period: String) = "$formattedPrice / $period"

    fun name(period: String) = NAMES[period] ?: period

    /** The plan card shows Play plans in the same shape as the portal's (Paddle) plans. */
    fun options(plans: List<PlayPlan>) = plans.map { PriceOption(it.period, name(it.period), it.label) }
}

/**
 * Google Play Billing for the Play Store build (BuildConfig.PLAY_STORE).
 *
 * The app only starts purchases and hands their tokens to the portal (`/api/v1/play/verify`); the portal checks each
 * one with Google and acknowledges it (pqvpn/portal/play.py).  [onPurchases] gets new purchases, on any thread.
 */
class PlayBilling(context: Context, private val onPurchases: (List<Purchase>) -> Unit) : PurchasesUpdatedListener {
    companion object {
        private const val TAG = "ShieldsBilling"
        private const val OK = BillingClient.BillingResponseCode.OK
    }

    private val client = BillingClient.newBuilder(context.applicationContext)
        .setListener(this)
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .enableAutoServiceReconnection()
        .build()
    @Volatile private var details: ProductDetails? = null

    private fun connect(ready: (Boolean) -> Unit) {
        if (client.isReady) return ready(true)
        client.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) = ready(result.responseCode == OK)
            override fun onBillingServiceDisconnected() {}   // reconnected automatically on the next call
        })
    }

    /** The subscription's base plans with Google's localized prices; empty when Play cannot be reached. */
    fun loadPlans(productId: String, done: (List<PlayPlan>) -> Unit) = connect { ok ->
        if (!ok) return@connect done(emptyList())
        val product = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(productId).setProductType(BillingClient.ProductType.SUBS).build()
        client.queryProductDetailsAsync(QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()) {
                result, products ->
            val d = products.productDetailsList.firstOrNull()
            details = d
            val plans = d?.subscriptionOfferDetails.orEmpty()
                .filter { it.offerId == null }   // base plans only (no trial or discount offers yet)
                .mapNotNull { offer ->
                    val phase = offer.pricingPhases.pricingPhaseList.lastOrNull() ?: return@mapNotNull null
                    val period = PlayPlans.period(phase.billingPeriod) ?: return@mapNotNull null
                    PlayPlan(period, PlayPlans.label(phase.formattedPrice, period), offer.offerToken)
                }
                .distinctBy { it.period }
                .sortedBy { PlayPlans.ORDER.indexOf(it.period) }
            done(if (result.responseCode == OK) plans else emptyList())
        }
    }

    /** Google Play's purchase sheet.  [accountRef] binds the purchase to the signed-in account (the portal checks it). */
    fun buy(activity: Activity, plan: PlayPlan, accountRef: String): Boolean {
        val d = details ?: return false
        val params = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(listOf(
                BillingFlowParams.ProductDetailsParams.newBuilder().setProductDetails(d).setOfferToken(plan.offerToken).build()))
            .setObfuscatedAccountId(accountRef)
            .build()
        return client.launchBillingFlow(activity, params).responseCode == OK
    }

    /** Subscriptions Google already holds for this Play user (restore after a reinstall; renewals). */
    fun restore(done: (List<Purchase>) -> Unit) = connect { ok ->
        if (!ok) return@connect done(emptyList())
        client.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder().setProductType(BillingClient.ProductType.SUBS).build()) { result, list ->
            done(if (result.responseCode == OK) list else emptyList())
        }
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        if (result.responseCode == OK && purchases != null) onPurchases(purchases)
        else if (result.responseCode != BillingClient.BillingResponseCode.USER_CANCELED) {
            Log.w(TAG, "purchase not completed (response ${result.responseCode})")
        }
    }

    fun end() = client.endConnection()
}
