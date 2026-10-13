// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 4226 (HOTP), RFC 6238 (TOTP) and Steam Guard codes. */
object OtpGenerator {
    private const val STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"
    private const val OFFSET_MASK = 0x0F
    private const val INT_MASK = 0x7FFFFFFF
    private const val MILLIS_PER_SECOND = 1000L
    private const val DECIMAL = 10L
    private val POWERS_OF_TEN =
        LongArray(OtpParams.MAX_DIGITS + 1).also {
            it[0] = 1
            for (i in 1 until it.size) it[i] = it[i - 1] * DECIMAL
        }

    /** RFC 4226 §5.3 dynamic truncation: a 31-bit integer from the HMAC of [counter]. */
    fun truncatedHash(
        secret: ByteArray,
        counter: Long,
        algorithm: OtpAlgorithm,
    ): Int {
        val mac = Mac.getInstance(algorithm.jcaName)
        mac.init(SecretKeySpec(secret, "RAW"))
        val hash = mac.doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(counter).array())
        val offset = hash[hash.size - 1].toInt() and OFFSET_MASK
        return ByteBuffer.wrap(hash, offset, Int.SIZE_BYTES).int and INT_MASK
    }

    /** HOTP value for [counter], zero-padded to [digits]. */
    fun hotp(
        secret: ByteArray,
        counter: Long,
        digits: Int = OtpParams.DEFAULT_DIGITS,
        algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
    ): String {
        require(digits in OtpParams.MIN_DIGITS..OtpParams.MAX_DIGITS) { "Unsupported digits" }
        val value = truncatedHash(secret, counter, algorithm).toLong() % POWERS_OF_TEN[digits]
        return value.toString().padStart(digits, '0')
    }

    /** TOTP time step (RFC 6238 `T`) at [epochMillis]. */
    fun timeStep(
        epochMillis: Long,
        period: Int,
    ): Long = Math.floorDiv(epochMillis / MILLIS_PER_SECOND, period.toLong())

    /** Steam Guard code: 5 characters of [STEAM_ALPHABET] from the truncated HMAC-SHA1. */
    fun steam(
        secret: ByteArray,
        timeStep: Long,
    ): String {
        var value = truncatedHash(secret, timeStep, OtpAlgorithm.SHA1)
        val sb = StringBuilder(OtpParams.STEAM_DIGITS)
        repeat(OtpParams.STEAM_DIGITS) {
            sb.append(STEAM_ALPHABET[value % STEAM_ALPHABET.length])
            value /= STEAM_ALPHABET.length
        }
        return sb.toString()
    }

    /** The code shown for [params] at [epochMillis] (HOTP uses its stored counter). */
    fun code(
        params: OtpParams,
        epochMillis: Long,
    ): String =
        when (params.type) {
            OtpType.TOTP -> hotp(params.secret, timeStep(epochMillis, params.period), params.digits, params.algorithm)
            OtpType.HOTP -> hotp(params.secret, params.counter, params.digits, params.algorithm)
            OtpType.STEAM -> steam(params.secret, timeStep(epochMillis, params.period))
        }

    /** Milliseconds until the current TOTP code of [period] seconds changes. */
    fun millisUntilNextStep(
        epochMillis: Long,
        period: Int,
    ): Long {
        val periodMillis = period * MILLIS_PER_SECOND
        return periodMillis - Math.floorMod(epochMillis, periodMillis)
    }
}
