// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import java.io.ByteArrayOutputStream

/** Why an `otpauth://` URI was rejected. Never contains the secret. */
class OtpUriException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Parser and writer of the Key Uri Format (`otpauth://TYPE/LABEL?PARAMS`) used by Google
 * Authenticator, Aegis and Ente. Lenient where real exports are sloppy (unencoded spaces in the
 * label, `+` for spaces in the query, Ente's `Algorithm.sha1`), strict on the secret.
 */
object OtpAuthUri {
    private const val SCHEME = "otpauth://"
    private const val HEX_RADIX = 16
    private const val PERCENT_ESCAPE_LENGTH = 3
    private const val BYTE_MASK = 0xFF
    private const val ASCII_LIMIT = 0x80

    /** Parses one URI. @throws OtpUriException if it is not a usable OTP account. */
    fun parse(uri: String): OtpParams {
        val text = uri.trim()
        if (!text.startsWith(SCHEME, ignoreCase = true)) throw OtpUriException("Not an otpauth:// URI")
        val rest = text.substring(SCHEME.length)
        val slash = rest.indexOf('/')
        if (slash < 0) throw OtpUriException("Missing label")
        val host = rest.substring(0, slash).lowercase()
        val afterHost = rest.substring(slash + 1)
        val queryStart = afterHost.indexOf('?')
        val rawLabel = if (queryStart < 0) afterHost else afterHost.substring(0, queryStart)
        val query = if (queryStart < 0) emptyMap() else parseQuery(afterHost.substring(queryStart + 1))
        return build(host, splitLabel(rawLabel, query["issuer"]), query)
    }

    private fun build(
        host: String,
        labelParts: Pair<String, String>,
        query: Map<String, String>,
    ): OtpParams {
        val type = parseType(host, query)
        val secret =
            try {
                Base32.decode(query["secret"] ?: fail("Missing secret"))
            } catch (e: IllegalArgumentException) {
                throw OtpUriException("Secret is not valid base32", e)
            }
        val (labelIssuer, account) = labelParts
        val steam = type == OtpType.STEAM
        val counter = query["counter"]?.let { it.trim().toLongOrNull() ?: fail("Invalid counter") }
        return try {
            OtpParams(
                type = type,
                secret = secret,
                algorithm = if (steam) OtpAlgorithm.SHA1 else parseAlgorithm(query["algorithm"]),
                digits = if (steam) OtpParams.STEAM_DIGITS else intParam(query, "digits") ?: OtpParams.DEFAULT_DIGITS,
                period = intParam(query, "period") ?: OtpParams.DEFAULT_PERIOD,
                counter = counter ?: 0,
                issuer = cleanIssuer(query["issuer"]) ?: labelIssuer,
                label = account,
                tags = EnteCodeDisplay.tags(query["codeDisplay"]),
            )
        } catch (e: IllegalArgumentException) {
            throw e as? OtpUriException ?: OtpUriException(e.message ?: "Invalid parameters", e)
        }
    }

    private fun parseType(
        host: String,
        query: Map<String, String>,
    ): OtpType =
        when {
            host == "steam" || query["encoder"].equals("steam", ignoreCase = true) -> OtpType.STEAM
            host == "totp" -> OtpType.TOTP
            host == "hotp" -> OtpType.HOTP
            else -> fail("Unsupported OTP type")
        }

    private fun parseAlgorithm(value: String?): OtpAlgorithm =
        if (value == null) OtpAlgorithm.SHA1 else OtpAlgorithm.parse(value) ?: fail("Unsupported algorithm")

    private fun fail(message: String): Nothing = throw OtpUriException(message)

    private fun intParam(
        query: Map<String, String>,
        name: String,
    ): Int? = query[name]?.let { it.trim().toIntOrNull() ?: throw OtpUriException("Invalid $name") }

    /** Ente sometimes leaks `period=…` into the issuer (see its `_getIssuer`). */
    private fun cleanIssuer(raw: String?): String? {
        val issuer = raw?.substringBefore("period=")?.trim()
        return issuer?.ifEmpty { null }
    }

    /**
     * Splits the *raw* label at its first literal `:` (Key URI Format): a colon inside a name is
     * percent-encoded by writers, so it is never taken for the separator. Writers that encode the
     * separator too (`Issuer%3Aaccount`, as some do) are recognised by the `issuer` parameter.
     */
    private fun splitLabel(
        rawLabel: String,
        issuerParam: String?,
    ): Pair<String, String> {
        val colon = rawLabel.indexOf(':')
        val label = decode(rawLabel, plusIsSpace = false)
        val issuer = issuerParam?.trim().orEmpty()
        return when {
            colon >= 0 -> {
                decode(rawLabel.substring(0, colon), plusIsSpace = false).trim() to
                    decode(rawLabel.substring(colon + 1), plusIsSpace = false).trim()
            }

            issuer.isNotEmpty() && label.startsWith("$issuer:") -> {
                issuer to label.substring(issuer.length + 1).trim()
            }

            // Without an issuer parameter an encoded separator is all there is to go by.
            issuer.isEmpty() && rawLabel.contains("%3A", ignoreCase = true) -> {
                label.substringBefore(':').trim() to label.substringAfter(':').trim()
            }

            else -> {
                "" to label.trim()
            }
        }
    }

    private fun parseQuery(query: String): Map<String, String> =
        query
            .split('&')
            .filter { it.isNotEmpty() }
            .associate { pair ->
                val eq = pair.indexOf('=')
                if (eq < 0) {
                    decode(pair, plusIsSpace = true) to ""
                } else {
                    val name = decode(pair.substring(0, eq), plusIsSpace = true)
                    name to decode(pair.substring(eq + 1), plusIsSpace = true)
                }
            }

    /** Percent-decoding as UTF-8; malformed escapes are kept literally. */
    internal fun decode(
        text: String,
        plusIsSpace: Boolean,
    ): String {
        val out = ByteArrayOutputStream(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            val hex =
                if (c == '%' && i + 2 <= text.lastIndex) {
                    text.substring(i + 1, i + PERCENT_ESCAPE_LENGTH).toIntOrNull(HEX_RADIX)
                } else {
                    null
                }
            when {
                hex != null -> {
                    out.write(hex)
                    i += PERCENT_ESCAPE_LENGTH
                }

                c == '+' && plusIsSpace -> {
                    out.write(' '.code)
                    i++
                }

                else -> {
                    out.write(c.toString().toByteArray(Charsets.UTF_8))
                    i++
                }
            }
        }
        return out.toString(Charsets.UTF_8.name())
    }

    private fun encode(text: String): String =
        buildString {
            for (b in text.toByteArray(Charsets.UTF_8)) {
                val c = b.toInt() and BYTE_MASK
                if (c < ASCII_LIMIT && (c.toChar().isLetterOrDigit() || c.toChar() in "-._~")) {
                    append(c.toChar())
                } else {
                    append('%').append("%02X".format(c))
                }
            }
        }

    /** Writes [params] as a URI that Google Authenticator, Aegis and Ente import. */
    fun format(params: OtpParams): String {
        val label =
            if (params.issuer.isEmpty()) {
                // A leading separator keeps a colon inside the name from being read as one.
                (if (params.label.contains(':')) ":" else "") + encode(params.label)
            } else {
                encode(params.issuer) + ":" + encode(params.label)
            }
        val sb = StringBuilder(SCHEME).append(params.type.uriName).append('/').append(label)
        sb.append("?secret=").append(Base32.encode(params.secret))
        if (params.issuer.isNotEmpty()) sb.append("&issuer=").append(encode(params.issuer))
        if (params.type != OtpType.STEAM) {
            sb.append("&algorithm=").append(params.algorithm.name)
            sb.append("&digits=").append(params.digits)
        }
        if (params.type == OtpType.HOTP) {
            sb.append("&counter=").append(params.counter)
        } else {
            sb.append("&period=").append(params.period)
        }
        return sb.toString()
    }
}
