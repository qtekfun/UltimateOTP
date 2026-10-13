// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.box.BoxCorruptedOrTamperedDataException
import com.ionspin.kotlin.crypto.scalarmult.ScalarMultiplication
import com.ionspin.kotlin.crypto.signature.InvalidSignatureException
import com.ionspin.kotlin.crypto.signature.Signature

/**
 * A device's two key pairs (crypto-format.md §5.1). The secret halves are wrapped by the Android
 * Keystore at rest; this class only holds them in memory while needed.
 */
class DeviceKeys(
    val ed25519Public: ByteArray,
    private val ed25519Secret: ByteArray,
    val x25519Public: ByteArray,
    private val x25519Secret: ByteArray,
) {
    val ed25519PublicB64u: String get() = B64u.encode(ed25519Public)
    val x25519PublicB64u: String get() = B64u.encode(x25519Public)

    fun sign(message: ByteArray): ByteArray {
        Sodium.init()
        return Signature.detached(message.asUByteArray(), ed25519Secret.asUByteArray()).asByteArray()
    }

    fun signB64u(message: ByteArray): String = B64u.encode(sign(message))

    /** Opens a `crypto_box_seal` addressed to this device. */
    fun openSealed(sealed: ByteArray): ByteArray {
        Sodium.init()
        return try {
            Box.sealOpen(sealed.asUByteArray(), x25519Public.asUByteArray(), x25519Secret.asUByteArray()).asByteArray()
        } catch (e: BoxCorruptedOrTamperedDataException) {
            throw CryptoException.AuthenticationFailed(cause = e)
        }
    }

    /** `ed25519_secret (64) || x25519_secret (32)`, for the Keystore wrap. Wipe after use. */
    fun exportSecrets(): ByteArray = ed25519Secret + x25519Secret

    fun wipe() {
        ed25519Secret.wipe()
        x25519Secret.wipe()
    }

    companion object {
        const val ED_SECRET_BYTES = 64
        const val X_SECRET_BYTES = 32
        const val PUBLIC_BYTES = 32
        const val SIGNATURE_BYTES = 64
        private const val ED_SEED_BYTES = 32

        fun generate(): DeviceKeys {
            Sodium.init()
            val sign = Signature.keypair()
            val box = Box.keypair()
            return DeviceKeys(
                sign.publicKey.asByteArray(),
                sign.secretKey.asByteArray(),
                box.publicKey.asByteArray(),
                box.secretKey.asByteArray(),
            )
        }

        /** Rebuilds the keys from [exportSecrets] (public halves are derived). */
        fun fromSecrets(secrets: ByteArray): DeviceKeys {
            if (secrets.size != ED_SECRET_BYTES + X_SECRET_BYTES) invalidFormat("bad device secrets")
            val ed = secrets.copyOfRange(0, ED_SECRET_BYTES)
            val x = secrets.copyOfRange(ED_SECRET_BYTES, secrets.size)
            return fromParts(ed, x)
        }

        /** For test vectors: Ed25519 from a 32-byte seed, X25519 from fixed secret bytes. */
        fun fromSeed(
            edSeed: ByteArray,
            xSecret: ByteArray,
        ): DeviceKeys {
            Sodium.init()
            require(edSeed.size == ED_SEED_BYTES) { "seed must be 32 bytes" }
            val sign = Signature.seedKeypair(edSeed.asUByteArray())
            return fromParts(sign.secretKey.asByteArray(), xSecret.copyOf())
        }

        private fun fromParts(
            edSecret: ByteArray,
            xSecret: ByteArray,
        ): DeviceKeys {
            Sodium.init()
            val edPublic = Signature.ed25519SkToPk(edSecret.asUByteArray()).asByteArray()
            val xPublic = ScalarMultiplication.scalarMultiplicationBase(xSecret.asUByteArray()).asByteArray()
            return DeviceKeys(edPublic, edSecret, xPublic, xSecret)
        }
    }
}

/** Ed25519 verification of another device's statements. */
object Ed25519 {
    fun verify(
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        Sodium.init()
        if (publicKey.size != DeviceKeys.PUBLIC_BYTES || signature.size != DeviceKeys.SIGNATURE_BYTES) return false
        return try {
            Signature.verifyDetached(signature.asUByteArray(), message.asUByteArray(), publicKey.asUByteArray())
            true
        } catch (_: InvalidSignatureException) {
            false
        }
    }

    fun verifyB64u(
        publicKeyB64u: String,
        message: ByteArray,
        signatureB64u: String,
    ): Boolean =
        try {
            verify(B64u.decode(publicKeyB64u), message, B64u.decode(signatureB64u))
        } catch (_: CryptoException.InvalidFormat) {
            false
        }
}
