// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support.autofill

/** What the autofill structure says about one input, flattened so the rules are testable. */
class FieldInfo(
    val autofillHints: List<String> = emptyList(),
    val idEntry: String? = null,
    val hint: String? = null,
    val label: String? = null,
    /** HTML `autocomplete` of a web field, if the browser exposes it. */
    val htmlAutocomplete: String? = null,
    val htmlType: String? = null,
    val numeric: Boolean = false,
    val password: Boolean = false,
    val maxLength: Int? = null,
)

/**
 * Finds the field that asks for a one-time code. OTP fields are rarely annotated, so beside the
 * explicit hints (`smsOTPCode`, `autocomplete="one-time-code"`) this scores names and labels in a few
 * languages, and never picks username, email or password fields. A guess, documented as such.
 */
object OtpFieldDetector {
    const val THRESHOLD = 4
    private const val EXPLICIT = 10
    private const val KEYWORD = 4
    private const val NUMERIC = 1
    private const val CODE_LENGTH = 1
    private const val BLOCKED = -10
    private const val MIN_CODE = 4
    private const val MAX_CODE = 10

    private val EXPLICIT_HINTS = setOf("smsotpcode", "onetimecode", "one-time-code", "otp", "totp", "2fa", "verificationcode")
    private val BLOCKING_HINTS =
        setOf("username", "emailaddress", "email", "password", "newpassword", "phone", "phonenumber", "name", "postalcode")
    private val KEYWORDS =
        listOf(
            "otp",
            "totp",
            "2fa",
            "mfa",
            "tfa",
            "two-factor",
            "twofactor",
            "two factor",
            "verification code",
            "verificationcode",
            "authenticator",
            "security code",
            "securitycode",
            "one-time",
            "onetime",
            "passcode",
            "auth code",
            "authcode",
            "codigo",
            "código",
            "verificacion",
            "verificación",
            "autenticacion",
            "autenticación",
            "bestätigungscode",
            "code de vérification",
        )

    fun score(f: FieldInfo): Int {
        val hints = f.autofillHints.map { it.lowercase() }
        val blocked =
            hints.any { it in BLOCKING_HINTS } || f.htmlType.equals("email", true) ||
                f.htmlAutocomplete?.lowercase() in BLOCKING_HINTS || (f.password && !f.numeric)
        val explicit = hints.any { it in EXPLICIT_HINTS } || f.htmlAutocomplete.equals("one-time-code", true)
        return when {
            blocked -> BLOCKED
            explicit -> EXPLICIT
            else -> keywordScore(f)
        }
    }

    private fun keywordScore(f: FieldInfo): Int {
        val text = listOfNotNull(f.idEntry, f.hint, f.label).joinToString(" ").lowercase()
        if (KEYWORDS.none { it in text }) return 0
        return KEYWORD + (if (f.numeric) NUMERIC else 0) + (if (f.maxLength in MIN_CODE..MAX_CODE) CODE_LENGTH else 0)
    }

    fun isOtpField(f: FieldInfo): Boolean = score(f) >= THRESHOLD
}
