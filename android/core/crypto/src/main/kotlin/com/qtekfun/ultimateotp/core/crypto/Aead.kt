// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.aead.AeadCorrupedOrTamperedDataException
import com.ionspin.kotlin.crypto.aead.AuthenticatedEncryptionWithAssociatedData

/** XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf_*`), random 24-byte nonces. */
object Aead {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16

    fun encrypt(
        key: ByteArray,
        nonce: ByteArray,
        message: ByteArray,
        ad: ByteArray,
    ): ByteArray {
        Sodium.init()
        return AuthenticatedEncryptionWithAssociatedData
            .xChaCha20Poly1305IetfEncrypt(
                message = message.asUByteArray(),
                associatedData = ad.asUByteArray(),
                nonce = nonce.asUByteArray(),
                key = key.asUByteArray(),
            ).asByteArray()
    }

    /** @throws CryptoException.AuthenticationFailed on a wrong key or tampered data. */
    fun decrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        ad: ByteArray,
    ): ByteArray {
        Sodium.init()
        if (ciphertext.size < TAG_BYTES) invalidFormat("ciphertext too short")
        return try {
            AuthenticatedEncryptionWithAssociatedData
                .xChaCha20Poly1305IetfDecrypt(
                    ciphertextAndTag = ciphertext.asUByteArray(),
                    associatedData = ad.asUByteArray(),
                    nonce = nonce.asUByteArray(),
                    key = key.asUByteArray(),
                ).asByteArray()
        } catch (e: AeadCorrupedOrTamperedDataException) {
            throw CryptoException.AuthenticationFailed(cause = e)
        }
    }
}
