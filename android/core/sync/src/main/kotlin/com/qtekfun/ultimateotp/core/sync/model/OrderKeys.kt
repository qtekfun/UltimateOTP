// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

/**
 * Fractional position keys for manual ordering: strings over `0-9A-Za-z` (ASCII order = digit
 * order) read as base-62 fractions, so there is always a key strictly between two others and
 * moving one item rewrites only that item. A key never ends in `0`.
 */
object OrderKeys {
    private const val DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    private const val BASE = 62
    private const val MIN_WIDTH = 3

    /** True for a key made of [DIGITS] only, not empty and not ending in `0`. */
    fun isValid(key: String): Boolean = key.isNotEmpty() && key.all { it in DIGITS } && key.last() != DIGITS[0]

    /** A key strictly between [lower] and [upper] (null = no bound). Requires `lower < upper`. */
    fun between(
        lower: String?,
        upper: String?,
    ): String {
        require(lower == null || isValid(lower)) { "invalid lower key" }
        require(upper == null || isValid(upper)) { "invalid upper key" }
        require(lower == null || upper == null || lower < upper) { "lower key must sort before upper key" }
        return midpoint(lower.orEmpty(), upper)
    }

    private fun midpoint(
        a: String,
        b: String?,
    ): String {
        // Skip the common prefix, treating a missing digit of `a` as zero.
        var n = 0
        while (b != null && n < b.length && (a.getOrNull(n) ?: DIGITS[0]) == b[n]) n++
        if (b != null && n > 0) return b.substring(0, n) + midpoint(a.drop(n), b.substring(n))
        val digitA = if (a.isEmpty()) 0 else DIGITS.indexOf(a[0])
        val digitB = if (b == null) BASE else DIGITS.indexOf(b[0])
        return when {
            digitB - digitA > 1 -> DIGITS[(digitA + digitB + 1) / 2].toString()

            // Consecutive digits: go below `b`'s first digit, or extend `a`.
            b != null && b.length > 1 -> b.substring(0, 1)

            else -> DIGITS[digitA] + midpoint(a.drop(1), null)
        }
    }

    /**
     * [count] evenly spaced keys in ascending order, the same on every device for the same
     * count (so two devices that both place a whole list for the first time agree).
     */
    fun initial(count: Int): List<String> {
        if (count <= 0) return emptyList()
        var width = MIN_WIDTH
        var span = pow(width)
        while (span < (count + 1).toLong() * BASE) span = pow(++width)
        // A multiple of the base keeps the last digit of every key at 1 (never 0).
        val step = span / (count + 1) / BASE * BASE
        return List(count) { i -> encode((i + 1) * step + 1, width) }
    }

    private fun pow(width: Int): Long {
        var v = 1L
        repeat(width) { v *= BASE }
        return v
    }

    private fun encode(
        value: Long,
        width: Int,
    ): String {
        val chars = CharArray(width)
        var v = value
        for (i in width - 1 downTo 0) {
            chars[i] = DIGITS[(v % BASE).toInt()]
            v /= BASE
        }
        return String(chars)
    }
}
