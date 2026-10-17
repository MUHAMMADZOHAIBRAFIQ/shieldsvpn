package com.shieldsvpn.vpn

import android.app.Application

class ShieldsApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannel(this)
    }
}
