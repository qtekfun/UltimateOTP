// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * PBKDF2 (RFC 8018) over a JCA HMAC, taking the password as bytes. Only for reading other apps'
 * backup files (2FAS, andOTP, scrypt's first and last step); our own formats use Argon2id.
 */
object Pbkdf2 {
    const val HMAC_SHA1 = "HmacSHA1"
    const val HMAC_SHA256 = "HmacSHA256"
    private const val INT_BYTES = 4
    private const val BYTE_MASK = 0xFF
    private const val BYTE_BITS = 8

    /**
     * @param hmac a JCA name, [HMAC_SHA1] or [HMAC_SHA256].
     * @throws CryptoException.InvalidFormat for out-of-range parameters.
     */
    fun derive(
        hmac: String,
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        length: Int,
    ): ByteArray {
        if (iterations < 1) invalidFormat("PBKDF2 iterations must be positive")
        if (length < 1) invalidFormat("PBKDF2 output length must be positive")
        val mac = Mac.getInstance(hmac)
        // An empty HMAC key is the same as one zero byte (the key is zero-padded), and JCA refuses it.
        mac.init(SecretKeySpec(if (password.isEmpty()) ByteArray(1) else password, hmac))
        val out = ByteArray(length)
        val blockLength = mac.macLength
        var block = 1
        var offset = 0
        while (offset < length) {
            mac.update(salt)
            mac.update(blockIndex(block))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (i in 1 until iterations) {
                u = mac.doFinal(u)
                for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            val n = minOf(blockLength, length - offset)
            t.copyInto(out, offset, 0, n)
            offset += n
            block++
        }
        return out
    }

    private fun blockIndex(i: Int) = ByteArray(INT_BYTES) { (i ushr (BYTE_BITS * (INT_BYTES - 1 - it)) and BYTE_MASK).toByte() }
}
