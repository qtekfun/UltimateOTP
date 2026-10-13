// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault.secure

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.io.File
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * [SecretStore] backed by an Android Keystore AES-256-GCM key (StrongBox when available) that
 * requires biometric or device-credential authentication within the last [validitySeconds]
 * (crypto-format.md §9). Ciphertexts live in `noBackupFilesDir`, and `allowBackup` is off.
 *
 * The key is not invalidated by a new fingerprint: that would lock the owner out of every
 * secret on the phone, while an attacker who can enroll a fingerprint already knows the device
 * credential.
 */
class KeystoreSecretStore(
    private val context: Context,
    private val validitySeconds: Int = DEFAULT_VALIDITY_SECONDS,
) : SecretStore {
    private val dir = File(context.noBackupFilesDir, "secrets").apply { mkdirs() }
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override val requiresUserAuthentication: Boolean
        get() = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true

    override fun put(
        name: String,
        secret: ByteArray,
    ) {
        val cipher = encryptCipher()
        val ct = cipher.doFinal(secret)
        file(name).writeBytes(byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + ct)
    }

    /** Initialising a cipher is where the Keystore checks the authentication window. */
    override fun checkUsable() {
        encryptCipher()
    }

    private fun encryptCipher(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key())
        } catch (e: UserNotAuthenticatedException) {
            throw AuthenticationRequiredException(e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException(e)
        }
        return cipher
    }

    override fun get(name: String): ByteArray? {
        val f = file(name)
        if (!f.exists()) return null
        val data = f.readBytes()
        val ivLength = data[0].toInt()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, existingKey(), GCMParameterSpec(TAG_BITS, data, 1, ivLength))
        } catch (e: UserNotAuthenticatedException) {
            throw AuthenticationRequiredException(e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException(e)
        }
        return cipher.doFinal(data, 1 + ivLength, data.size - 1 - ivLength)
    }

    override fun delete(name: String) {
        file(name).delete()
    }

    override fun contains(name: String): Boolean = file(name).exists()

    private fun file(name: String) = File(dir, "$name.bin")

    private fun existingKey(): SecretKey = (keyStore.getKey(ALIAS, null) as? SecretKey) ?: throw KeyInvalidatedException()

    private fun key(): SecretKey = (keyStore.getKey(ALIAS, null) as? SecretKey) ?: generate()

    private fun generate(): SecretKey {
        val strongBox =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generate(strongBox)
        } catch (e: ProviderException) {
            // StrongBoxUnavailableException (API 28) is a ProviderException.
            if (!strongBox) throw e
            generate(false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val builder =
            KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_BITS)
        if (requiresUserAuthentication) {
            builder.setUserAuthenticationRequired(true)
            builder.setInvalidatedByBiometricEnrollment(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    validitySeconds,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(validitySeconds)
            }
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "uotp_secrets_v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
        const val KEY_BITS = 256
        const val DEFAULT_VALIDITY_SECONDS = 30
    }
}
