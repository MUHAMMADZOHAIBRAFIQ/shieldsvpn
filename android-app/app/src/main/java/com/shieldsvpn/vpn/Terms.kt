package com.shieldsvpn.vpn

import android.content.Context
import java.io.File

/**
 * Acceptance of the User Agreement (android-app/ui/src/terms.ts, public/terms.html).
 *
 * Kept in the app's no-backup directory, so it is asked once per installation: a new install (or "Clear storage")
 * starts without it, and Android's backup cannot restore it onto another phone.  Raise [VERSION] whenever the
 * agreement changes so that everyone accepts the new text.
 */
object Terms {
    const val VERSION = "2026-10-31"
    private const val FILE = "terms-accepted"

    /** The stored acceptance is for this version of the agreement. */
    fun matches(stored: String?): Boolean = stored?.trim() == VERSION

    fun accepted(ctx: Context): Boolean =
        matches(runCatching { File(ctx.noBackupFilesDir, FILE).readText() }.getOrNull())

    fun accept(ctx: Context) {
        File(ctx.noBackupFilesDir, FILE).writeText(VERSION)
    }
}
