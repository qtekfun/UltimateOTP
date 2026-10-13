// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support

import com.qtekfun.ultimateotp.core.support.autofill.AutofillCandidate
import com.qtekfun.ultimateotp.core.support.autofill.AutofillMatcher
import com.qtekfun.ultimateotp.core.support.autofill.FieldInfo
import com.qtekfun.ultimateotp.core.support.autofill.MatchKind
import com.qtekfun.ultimateotp.core.support.autofill.OtpFieldDetector
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AutofillTest {
    private fun c(
        id: String,
        issuer: String,
        vararg assoc: String,
    ) = AutofillCandidate(id, issuer, assoc.toList())

    private val entries =
        listOf(
            c("gh", "GitHub"),
            c("gh2", "github.com"),
            c("goog", "Google", "accounts.google.com", "com.google.android.gms"),
            c("bank", "My Bank", "com.mybank.app", "online.mybank.example"),
            c("short", "X"),
            c("aws", "Amazon Web Services", "signin.aws.amazon.com"),
        )

    private fun ids(
        pkg: String?,
        domain: String?,
        own: String? = null,
    ) = AutofillMatcher.match(entries, pkg, domain, own).map { it.candidate.id }

    @Test
    fun `explicit associations match packages and parent domains`() {
        assertEquals(listOf("goog"), ids(null, "accounts.google.com"))
        assertEquals(listOf("goog"), ids(null, "https://accounts.google.com".removePrefix("https://")))
        assertEquals(listOf("goog"), ids("com.google.android.gms", null))
        assertEquals(listOf("bank"), ids("com.mybank.app", null))
        assertEquals(listOf("bank"), ids(null, "login.online.mybank.example"))
        assertEquals(listOf("aws"), ids(null, "eu.signin.aws.amazon.com"))
    }

    @Test
    fun `issuer guesses for domains and packages, weaker than explicit ones`() {
        val m = AutofillMatcher.match(entries, null, "github.com")
        assertEquals(setOf("gh", "gh2"), m.map { it.candidate.id }.toSet())
        assertTrue(m.all { it.kind == MatchKind.ISSUER_DOMAIN })
        assertEquals(listOf("gh"), AutofillMatcher.match(entries, "com.github.android", null).map { it.candidate.id })
        assertEquals(MatchKind.ISSUER_PACKAGE, AutofillMatcher.match(entries, "com.github.android", null).single().kind)
        // The explicit association ranks first when both kinds match.
        val both =
            AutofillMatcher.match(listOf(c("a", "Example"), c("b", "Other", "example.com")), null, "www.example.com")
        assertEquals(listOf("b", "a"), both.map { it.candidate.id })
    }

    @Test
    fun `no match for unknown, short issuers, similar domains or the app itself`() {
        assertTrue(ids(null, null).isEmpty())
        assertTrue(ids("com.unrelated.app", "unrelated.example").isEmpty())
        assertTrue(ids(null, "x.com").isEmpty()) // issuer "X" is too short to guess from
        assertTrue(ids(null, "notgithub.com").isEmpty())
        assertTrue(ids(null, "github.com.evil.example").isEmpty())
        assertTrue(ids("com.qtekfun.ultimateotp", null, own = "com.qtekfun.ultimateotp").isEmpty())
        assertTrue(ids(null, "evilgoogle.com").isEmpty())
    }

    @Test
    fun `two level suffixes are handled and the result is bounded`() {
        assertEquals(listOf("bbc"), AutofillMatcher.match(listOf(c("bbc", "BBC")), null, "account.bbc.co.uk").map { it.candidate.id })
        val many = (1..20).map { c("id$it", "Site", "site.example") }
        assertEquals(5, AutofillMatcher.match(many, null, "site.example").size)
    }

    @Test
    fun `host normalisation strips scheme, port, path and www`() {
        assertEquals("example.com", AutofillMatcher.hostOf("https://user@WWW.Example.com:8443/login?x=1#f"))
    }

    // ---- field detection ----------------------------------------------------------------------------

    @Test
    fun `explicit hints and autocomplete one-time-code are accepted`() {
        assertTrue(OtpFieldDetector.isOtpField(FieldInfo(autofillHints = listOf("smsOTPCode"))))
        assertTrue(OtpFieldDetector.isOtpField(FieldInfo(htmlAutocomplete = "one-time-code")))
    }

    @Test
    fun `names and labels in several languages are scored`() {
        assertTrue(OtpFieldDetector.isOtpField(FieldInfo(idEntry = "totp_code", numeric = true)))
        assertTrue(OtpFieldDetector.isOtpField(FieldInfo(hint = "Código de verificación")))
        assertTrue(OtpFieldDetector.isOtpField(FieldInfo(label = "Enter your authenticator code", maxLength = 6)))
        assertTrue(OtpFieldDetector.isOtpField(FieldInfo(idEntry = "mfa-token")))
    }

    @Test
    fun `usernames, emails, passwords and plain fields are never taken`() {
        assertFalse(OtpFieldDetector.isOtpField(FieldInfo(autofillHints = listOf("username"), idEntry = "otp_user")))
        assertFalse(OtpFieldDetector.isOtpField(FieldInfo(password = true, idEntry = "otp password")))
        assertFalse(OtpFieldDetector.isOtpField(FieldInfo(htmlType = "email", hint = "otp email")))
        assertFalse(OtpFieldDetector.isOtpField(FieldInfo(idEntry = "search_box", hint = "Search")))
        assertFalse(OtpFieldDetector.isOtpField(FieldInfo()))
        assertFalse(OtpFieldDetector.isOtpField(FieldInfo(numeric = true, maxLength = 6)))
    }
}
