package com.shieldsvpn.vpn

import android.content.Context
import android.net.Uri
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.security.GeneralSecurityException

class ProfileImportException(message: String) : Exception(message)

/** What the UI shows about the installed profile (public information only). */
data class ProfileSummary(
    val account: String,
    val server: String,
    val serverName: String,
    val tunnelAddress: String,
    val expiresEpochSeconds: Long,
    val fullTunnel: Boolean,
    val encryption: String,
    val portalUrl: String,
    val keyAlg: String = "",
    /** Certificate serial (hex); binds the encrypted secrets to this profile. */
    val serial: String = "",
) {
    companion object {
        fun fromJson(o: JSONObject) = ProfileSummary(
            account = o.optString("account"),
            server = o.optString("server"),
            serverName = o.optString("server_name"),
            tunnelAddress = o.optString("tunnel_address"),
            expiresEpochSeconds = o.optLong("expires"),
            fullTunnel = o.optBoolean("full_tunnel"),
            encryption = o.optString("encryption"),
            portalUrl = o.optString("portal_url"),
            keyAlg = o.optString("key_alg"),
            serial = o.optString("serial"),
        )
    }
}

class ProfileSecrets(val keyPem: String, val psk: String)

/**
 * The installed VPN profile.
 *
 * Layout (all app-private, excluded from backups):
 *   files/profile/            client.toml (without psk_file), <user>.crt, ca.crt, summary.json
 *   no_backup/profile.secrets private key + PSK, AES-256-GCM under an Android Keystore key (SecretBox)
 *
 * Profiles are the ZIP files the portal already issues ("Download VPN profile").  Python validates them
 * (pqvpn.android_client.import_profile): the certificate must chain to the bundled CA, be a client
 * certificate that is valid now, and match the private key.  Nothing is ever extracted from the ZIP by
 * path, so a crafted archive cannot write outside the staging directory.
 */
object ProfileStore {
    private const val MAX_ZIP = 4 * 1024 * 1024
    private const val SUMMARY = "summary.json"
    private val lock = Any()

    fun profileDir(ctx: Context) = File(ctx.filesDir, "profile")
    private fun secretsFile(ctx: Context) = File(ctx.noBackupFilesDir, "profile.secrets")

    fun hasProfile(ctx: Context): Boolean =
        File(profileDir(ctx), "client.toml").isFile && secretsFile(ctx).isFile

    fun summary(ctx: Context): ProfileSummary? {
        if (!hasProfile(ctx)) return null
        return runCatching { ProfileSummary.fromJson(JSONObject(File(profileDir(ctx), SUMMARY).readText())) }.getOrNull()
    }

    /** Validates and installs a profile ZIP.  Runs Python: call on a background thread. */
    fun importProfile(ctx: Context, uri: Uri): ProfileSummary {
        val bytes = ctx.contentResolver.openInputStream(uri)?.use { readLimited(it) }
            ?: throw ProfileImportException("The file cannot be opened.")
        val staging = File(ctx.filesDir, "profile-staging")
        staging.deleteRecursively()
        try {
            val raw = PythonRuntime.androidClient(ctx).callAttr("import_profile_json", bytes, staging.absolutePath)
            val result = JSONObject(raw.toString())
            if (!result.optBoolean("ok")) throw ProfileImportException(result.optString("error", "unknown error"))
            val summary = result.getJSONObject("summary")
            // The serial binds the sealed key to this certificate, so a half-finished replacement is detected.
            val secrets = result.getJSONObject("secrets").put("serial", summary.optString("serial"))
            val sealed = SecretBox.seal(secrets.toString().toByteArray(Charsets.UTF_8))
            File(staging, SUMMARY).writeText(summary.toString())
            install(ctx, staging, sealed)
            return ProfileSummary.fromJson(summary)
        } finally {
            staging.deleteRecursively()
        }
    }

    private fun install(ctx: Context, staging: File, sealedSecrets: ByteArray) = synchronized(lock) {
        val dir = profileDir(ctx)
        val secrets = secretsFile(ctx)
        val old = File(ctx.filesDir, "profile-old").apply { deleteRecursively() }
        val tmpSecrets = File(secrets.path + ".tmp")
        tmpSecrets.parentFile?.mkdirs()
        tmpSecrets.writeBytes(sealedSecrets)
        if (dir.exists() && !dir.renameTo(old)) throw ProfileImportException("cannot replace the old profile")
        if (!staging.renameTo(dir)) {
            old.renameTo(dir)
            throw ProfileImportException("cannot install the profile")
        }
        if (!tmpSecrets.renameTo(secrets)) throw ProfileImportException("cannot store the encrypted key")
        old.deleteRecursively()
    }

    /** Do these sealed secrets belong to the installed profile?  (Installs older than the serial binding pass.) */
    fun secretsMatchProfile(secrets: JSONObject, profileSerial: String): Boolean {
        val s = secrets.optString("serial", "")
        return s.isEmpty() || profileSerial.isEmpty() || s.equals(profileSerial, ignoreCase = true)
    }

    private fun openSecrets(file: File): JSONObject = try {
        JSONObject(String(SecretBox.open(file.readBytes()), Charsets.UTF_8))
    } catch (e: GeneralSecurityException) {
        // Keystore key replaced or reset (e.g. after a device restore); the ciphertext can never be opened again.
        throw ProfileImportException("The stored private key can no longer be decrypted (the Android Keystore key " +
            "was reset). Import the profile again.")
    } catch (e: IllegalStateException) {
        throw ProfileImportException(e.message ?: "The stored private key cannot be read. Import the profile again.")
    } catch (e: IllegalArgumentException) {
        throw ProfileImportException("The stored private key is damaged. Import the profile again.")
    }

    fun loadSecrets(ctx: Context): ProfileSecrets = synchronized(lock) {
        val file = secretsFile(ctx)
        val serial = summary(ctx)?.serial ?: ""
        var o = openSecrets(file)
        if (!secretsMatchProfile(o, serial)) {
            // An import was interrupted between moving the profile and moving its secrets: finish it if the
            // new secrets are still in the temporary file, otherwise refuse (never pair a key with another cert).
            val tmp = File(file.path + ".tmp")
            val pending = if (tmp.isFile) runCatching { openSecrets(tmp) }.getOrNull() else null
            if (pending != null && pending.optString("serial").isNotEmpty() && secretsMatchProfile(pending, serial) &&
                tmp.renameTo(file)
            ) {
                o = pending
            } else {
                throw ProfileImportException("The stored private key belongs to a different profile (an earlier " +
                    "import was interrupted). Import the profile again.")
            }
        }
        ProfileSecrets(o.getString("key_pem"), o.optString("psk", ""))
    }

    fun remove(ctx: Context) = synchronized(lock) {
        profileDir(ctx).deleteRecursively()
        secretsFile(ctx).delete()
        SecretBox.deleteKey()
    }

    private fun readLimited(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > MAX_ZIP) throw ProfileImportException("This file is too large to be a ShieldsVPN profile.")
        }
        return out.toByteArray()
    }
}
