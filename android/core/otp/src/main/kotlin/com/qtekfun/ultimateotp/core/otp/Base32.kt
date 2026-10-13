// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

/** RFC 4648 base32, the encoding of OTP secrets in `otpauth://` URIs. */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val BITS_PER_CHAR = 5
    private const val BITS_PER_BYTE = 8
    private const val CHAR_MASK = 0x1F
    private const val BYTE_MASK = 0xFF

    /**
     * Decodes [text], tolerating what people paste: lower case, spaces, dashes and `=` padding.
     *
     * @throws IllegalArgumentException on any other character or on an empty secret.
     */
    fun decode(text: String): ByteArray {
        val clean = text.uppercase().filterNot { it == ' ' || it == '-' || it == '=' }
        require(clean.isNotEmpty()) { "Empty base32 secret" }
        val out = ArrayList<Byte>(clean.length * BITS_PER_CHAR / BITS_PER_BYTE)
        var buffer = 0
        var bits = 0
        for (c in clean) {
            val value = ALPHABET.indexOf(c)
            require(value >= 0) { "Invalid base32 character" }
            buffer = (buffer shl BITS_PER_CHAR) or value
            bits += BITS_PER_CHAR
            if (bits >= BITS_PER_BYTE) {
                bits -= BITS_PER_BYTE
                out.add(((buffer shr bits) and BYTE_MASK).toByte())
            }
        }
        return out.toByteArray()
    }

    /** Encodes [data] in upper case without padding (the canonical form of the vault, §6.1). */
    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size * BITS_PER_BYTE + BITS_PER_CHAR - 1) / BITS_PER_CHAR)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl BITS_PER_BYTE) or (b.toInt() and BYTE_MASK)
            bits += BITS_PER_BYTE
            while (bits >= BITS_PER_CHAR) {
                bits -= BITS_PER_CHAR
                sb.append(ALPHABET[(buffer shr bits) and CHAR_MASK])
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (BITS_PER_CHAR - bits)) and CHAR_MASK])
        return sb.toString()
    }

    /** True if [text] decodes to a non-empty secret. */
    fun isValid(text: String): Boolean = runCatching { decode(text).isNotEmpty() }.getOrDefault(false)
}
