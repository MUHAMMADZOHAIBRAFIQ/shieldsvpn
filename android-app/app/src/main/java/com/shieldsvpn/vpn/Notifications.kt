package com.shieldsvpn.vpn

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

object Notifications {
    const val CHANNEL = "vpn_status"
    const val ID = 1

    fun createChannel(ctx: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val ch = NotificationChannel(CHANNEL, ctx.getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
        ch.description = ctx.getString(R.string.notif_channel_desc)
        ch.setShowBadge(false)
        ctx.getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    fun build(ctx: Context, s: VpnUiState): Notification {
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            ctx, 1, Intent(ctx, ShieldsVpnService::class.java).setAction(ShieldsVpnService.ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val (title, text) = when (s.phase) {
            Phase.CONNECTED -> "ShieldsVPN · ${ctx.getString(R.string.state_connected)}" to
                listOf(s.tunnelAddress.substringBefore('/'), s.encryption).filter { it.isNotBlank() }.joinToString(" · ")
            Phase.RECONNECTING -> "ShieldsVPN · ${ctx.getString(R.string.state_reconnecting)}" to ctx.getString(R.string.sub_reconnecting)
            Phase.ERROR -> "ShieldsVPN · ${ctx.getString(R.string.state_error)}" to s.message
            Phase.DISCONNECTING -> "ShieldsVPN" to ctx.getString(R.string.sub_disconnecting)
            Phase.PREPARING -> "ShieldsVPN · ${ctx.getString(R.string.state_preparing)}" to ctx.getString(R.string.sub_preparing)
            else -> "ShieldsVPN · ${ctx.getString(R.string.state_connecting)}" to s.server
        }
        return NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setColor(ContextCompat.getColor(ctx, if (s.phase == Phase.CONNECTED) R.color.state_on else R.color.brand))
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(open)
            .addAction(0, ctx.getString(R.string.notif_disconnect), stop)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    fun update(ctx: Context, s: VpnUiState) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return  // the foreground-service notification still shows in the task manager
        ctx.getSystemService(NotificationManager::class.java).notify(ID, build(ctx, s))
    }
}
