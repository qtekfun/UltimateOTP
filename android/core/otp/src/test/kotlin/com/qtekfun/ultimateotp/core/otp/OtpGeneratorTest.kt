// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class OtpGeneratorTest {
    private val sha1Seed = "12345678901234567890".toByteArray()
    private val sha256Seed = "12345678901234567890123456789012".toByteArray()
    private val sha512Seed = "1234567890123456789012345678901234567890123456789012345678901234".toByteArray()

    /** RFC 4226 Appendix D. */
    @ParameterizedTest
    @CsvSource(
        "0, 755224",
        "1, 287082",
        "2, 359152",
        "3, 969429",
        "4, 338314",
        "5, 254676",
        "6, 287922",
        "7, 162583",
        "8, 399871",
        "9, 520489",
    )
    fun `RFC 4226 HOTP vectors`(
        counter: Long,
        expected: String,
    ) {
        assertEquals(expected, OtpGenerator.hotp(sha1Seed, counter, 6, OtpAlgorithm.SHA1))
    }

    /** RFC 6238 Appendix B (8 digits, 30 s). */
    @ParameterizedTest
    @CsvSource(
        "59, 94287082, 46119246, 90693936",
        "1111111109, 07081804, 68084774, 25091201",
        "1111111111, 14050471, 67062674, 99943326",
        "1234567890, 89005924, 91819424, 93441116",
        "2000000000, 69279037, 90698825, 38618901",
        "20000000000, 65353130, 77737706, 47863826",
    )
    fun `RFC 6238 TOTP vectors`(
        seconds: Long,
        sha1: String,
        sha256: String,
        sha512: String,
    ) {
        val millis = seconds * 1000

        fun totp(
            seed: ByteArray,
            alg: OtpAlgorithm,
        ) = OtpGenerator.code(OtpParams(OtpType.TOTP, seed, alg, digits = 8), millis)
        assertEquals(sha1, totp(sha1Seed, OtpAlgorithm.SHA1))
        assertEquals(sha256, totp(sha256Seed, OtpAlgorithm.SHA256))
        assertEquals(sha512, totp(sha512Seed, OtpAlgorithm.SHA512))
    }

    /** Values from an independent Python implementation of Steam Guard's encoding. */
    @Test
    fun `Steam codes`() {
        assertEquals("PV9M4", OtpGenerator.steam(sha1Seed, 1))
        assertEquals("PY4YB", OtpGenerator.steam(sha1Seed, 37_037_036))
        val params = OtpParams(OtpType.STEAM, sha1Seed, digits = OtpParams.STEAM_DIGITS)
        assertEquals("5PP3V", OtpGenerator.code(params, 1_111_111_111_000))
    }

    @Test
    fun `HOTP uses the stored counter`() {
        val params = OtpParams(OtpType.HOTP, sha1Seed, counter = 7)
        assertEquals("162583", OtpGenerator.code(params, 0))
        assertEquals("4755224", OtpGenerator.hotp(sha1Seed, 0, 7))
    }

    @Test
    fun `time until the next step`() {
        assertEquals(30_000, OtpGenerator.millisUntilNextStep(60_000, 30))
        assertEquals(1, OtpGenerator.millisUntilNextStep(59_999, 30))
        assertEquals(0L, OtpGenerator.timeStep(29_999, 30))
        assertEquals(1L, OtpGenerator.timeStep(30_000, 30))
    }
}
