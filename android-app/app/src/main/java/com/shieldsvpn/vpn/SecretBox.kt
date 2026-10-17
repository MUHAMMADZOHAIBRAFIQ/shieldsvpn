package com.shieldsvpn.vpn

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM encryption under a non-exportable Android Keystore key.
 *
 * Used for the profile's private key and PSK, so the files in app storage hold only ciphertext; the key
 * that opens them never leaves the Keystore (hardware-backed where the device supports it).
 */
object SecretBox {
    private const val ALIAS = "shieldsvpn-profile-secrets-v1"
    private const val VERSION: Byte = 1
    private const val TAG_BITS = 128
    private val AAD = "shieldsvpn profile secrets v1".toByteArray()

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(create: Boolean): SecretKey? {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    /** Returns version || 12-byte IV || ciphertext+tag. */
    fun seal(plaintext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key(create = true))
        c.updateAAD(AAD)
        val ct = c.doFinal(plaintext)
        val iv = c.iv
        require(iv.size == 12) { "unexpected GCM IV length" }
        return byteArrayOf(VERSION) + iv + ct
    }

    fun open(blob: ByteArray): ByteArray {
        require(blob.size > 1 + 12 + 16 && blob[0] == VERSION) { "secrets file is damaged" }
        val k = key(create = false) ?: throw IllegalStateException("the Keystore key is gone; import the profile again")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(TAG_BITS, blob, 1, 12))
        c.updateAAD(AAD)
        return c.doFinal(blob, 13, blob.size - 13)
    }

    fun deleteKey() {
        runCatching { keyStore().deleteEntry(ALIAS) }
    }
}
