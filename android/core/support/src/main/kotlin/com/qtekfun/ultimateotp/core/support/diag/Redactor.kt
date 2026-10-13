// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support.diag

/**
 * Removes what must never reach the diagnostics log: OTP URIs and secrets, codes, email
 * addresses, tokens and ids, and the path, query and credentials of URLs (the host is kept so a
 * connection problem can be read). Applied to every message and stack trace at write time, in
 * addition to callers not passing such data in the first place.
 */
object Redactor {
    private val OTP_URI = Regex("""(?i)\botpauth(?:-migration)?://\S*""")
    private val URL = Regex("""(?i)\b([a-z][a-z0-9+.-]*)://(?:[^/\s@]*@)?([^/\s?#]+)[^\s]*""")
    private val EMAIL = Regex("""[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+""")
    private val PREFIXED_ID = Regex("""\b(?:uoe|uop|dev|acc|pair|srp|c)_[A-Za-z0-9_-]{6,}""")
    private val UUID = Regex("""\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""")
    private val BEARER = Regex("""(?i)\b(bearer|token|password|secret|authorization)\b\s*[:=]?\s*\S+""")
    private val LONG_BASE32 = Regex("""\b[A-Z2-7]{16,}=*""")
    private val LONG_HEX = Regex("""\b[0-9a-fA-F]{24,}\b""")
    private val LONG_B64 = Regex("""[A-Za-z0-9+/_-]{32,}={0,2}""")
    private val CODE = Regex("""(?<![\d.])\d{6,8}(?![\d.])""")
    private val IPV4 = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}\b""")

    fun redact(text: String): String {
        var t = text
        t = OTP_URI.replace(t, "<otp-uri>")
        t = URL.replace(t) { "${it.groupValues[1]}://${it.groupValues[2]}/<redacted>" }
        t = EMAIL.replace(t, "<email>")
        t = BEARER.replace(t) { "${it.groupValues[1]} <redacted>" }
        t = PREFIXED_ID.replace(t, "<id>")
        t = UUID.replace(t, "<uuid>")
        t = LONG_B64.replace(t, "<token>")
        t = LONG_BASE32.replace(t, "<secret>")
        t = LONG_HEX.replace(t, "<hex>")
        t = IPV4.replace(t, "<ip>")
        t = CODE.replace(t, "<code>")
        return t
    }

    /** A stack trace with redacted messages, class names and frames kept. */
    fun redactTrace(error: Throwable): String = redact(error.stackTraceToString())
}
