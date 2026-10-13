// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import kotlin.math.ln
import kotlin.math.min

/**
 * A rough strength hint for the master password, shown while choosing it (like Ente Auth's).
 * The password encrypts the vault key that the server keeps, and there is no reset without the
 * recovery key, so [WEAK] passwords are refused. It is an estimate, not a guarantee: character
 * classes, length and repetition, plus a short list of the most common passwords.
 */
enum class PasswordStrength {
    TOO_SHORT,
    WEAK,
    FAIR,
    STRONG,
    ;

    val acceptable: Boolean get() = this == FAIR || this == STRONG

    companion object {
        const val MIN_LENGTH = 8
        private const val FAIR_BITS = 50.0
        private const val STRONG_BITS = 70.0
        private const val MIN_DISTINCT = 5
        private const val LOWER = 26
        private const val UPPER = 26
        private const val DIGITS = 10
        private const val SYMBOLS = 33
        private val COMMON =
            setOf(
                "password",
                "password1",
                "password123",
                "12345678",
                "123456789",
                "1234567890",
                "qwertyuiop",
                "iloveyou",
                "11111111",
                "00000000",
                "abcd1234",
                "qwerty123",
                "letmein1",
                "sunshine",
                "princess",
                "football",
                "baseball",
                "superman",
                "trustno1",
                "welcome1",
                "passw0rd",
                "p@ssw0rd",
                "1q2w3e4r",
            )

        fun of(password: String): PasswordStrength {
            val distinct = password.toSet().size
            return when {
                password.codePointCount(0, password.length) < MIN_LENGTH -> TOO_SHORT
                distinct < MIN_DISTINCT || password.lowercase() in COMMON -> WEAK
                bits(password, distinct) >= STRONG_BITS -> STRONG
                bits(password, distinct) >= FAIR_BITS -> FAIR
                else -> WEAK
            }
        }

        private fun bits(
            password: String,
            distinct: Int,
        ): Double {
            var pool = 0
            if (password.any { it.isLowerCase() }) pool += LOWER
            if (password.any { it.isUpperCase() }) pool += UPPER
            if (password.any { it.isDigit() }) pool += DIGITS
            if (password.any { !it.isLetterOrDigit() }) pool += SYMBOLS
            // Repeated characters add little: count at most two uses of each distinct one.
            return ln(pool.toDouble()) / ln(2.0) * min(password.length, 2 * distinct)
        }
    }
}
