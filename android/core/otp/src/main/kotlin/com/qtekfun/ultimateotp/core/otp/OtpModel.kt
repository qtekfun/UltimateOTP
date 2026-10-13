// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

/** HMAC hash of RFC 4226/6238. [jcaName] is the javax.crypto name. */
enum class OtpAlgorithm(
    val jcaName: String,
) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512"),
    ;

    companion object {
        /** Lenient parse: `sha1`, `SHA-256`, Ente's `Algorithm.sha512`... Unknown values are null. */
        fun parse(value: String?): OtpAlgorithm? {
            val v = value?.substringAfterLast('.')?.replace("-", "")?.uppercase() ?: return null
            return entries.firstOrNull { it.name == v }
        }
    }
}

enum class OtpType(
    val uriName: String,
) {
    TOTP("totp"),
    HOTP("hotp"),

    /** Steam Guard: TOTP/SHA1/30 s, 5 characters from a custom alphabet. */
    STEAM("steam"),
}

/**
 * Everything needed to generate codes for one account. [secret] is the raw key (not base32).
 * The class holds a secret: never log it or put it in an exception message.
 */
class OtpParams(
    val type: OtpType,
    val secret: ByteArray,
    val algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
    val digits: Int = DEFAULT_DIGITS,
    val period: Int = DEFAULT_PERIOD,
    val counter: Long = 0,
    val issuer: String = "",
    val label: String = "",
    val tags: List<String> = emptyList(),
) {
    init {
        require(secret.isNotEmpty()) { "Empty secret" }
        require(digits in MIN_DIGITS..MAX_DIGITS) { "Digits must be in $MIN_DIGITS..$MAX_DIGITS" }
        require(period in 1..MAX_PERIOD) { "Period must be in 1..$MAX_PERIOD" }
        require(counter >= 0) { "Negative counter" }
    }

    fun copy(
        type: OtpType = this.type,
        secret: ByteArray = this.secret,
        algorithm: OtpAlgorithm = this.algorithm,
        digits: Int = this.digits,
        period: Int = this.period,
        counter: Long = this.counter,
        issuer: String = this.issuer,
        label: String = this.label,
        tags: List<String> = this.tags,
    ): OtpParams = OtpParams(type, secret, algorithm, digits, period, counter, issuer, label, tags)

    override fun equals(other: Any?): Boolean =
        other is OtpParams &&
            type == other.type &&
            secret.contentEquals(other.secret) &&
            algorithm == other.algorithm &&
            digits == other.digits &&
            period == other.period &&
            counter == other.counter &&
            issuer == other.issuer &&
            label == other.label &&
            tags == other.tags

    override fun hashCode(): Int =
        listOf(type, algorithm, digits, period, counter, issuer, label, tags)
            .hashCode() * HASH_MULTIPLIER + secret.contentHashCode()

    /** No secret in here: safe for logs and crash reports. */
    override fun toString(): String = "OtpParams(type=$type, issuer=<redacted>, digits=$digits, period=$period)"

    companion object {
        const val DEFAULT_DIGITS = 6
        const val DEFAULT_PERIOD = 30
        const val STEAM_DIGITS = 5
        const val MIN_DIGITS = 5
        const val MAX_DIGITS = 10
        const val MAX_PERIOD = 86_400
        private const val HASH_MULTIPLIER = 31
    }
}
