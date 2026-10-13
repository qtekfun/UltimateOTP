// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class OtpAuthUriTest {
    @Test
    fun `Key Uri Format example`() {
        val p =
            OtpAuthUri.parse(
                "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ" +
                    "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
            )
        assertEquals(OtpType.TOTP, p.type)
        assertEquals("ACME Co", p.issuer)
        assertEquals("john.doe@email.com", p.label)
        assertEquals(OtpAlgorithm.SHA1, p.algorithm)
        assertEquals(6, p.digits)
        assertEquals(30, p.period)
        assertEquals("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", Base32.encode(p.secret))
    }

    @Test
    fun `defaults, label without issuer and HOTP counter`() {
        val totp = OtpAuthUri.parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        assertEquals("", totp.issuer)
        assertEquals("alice", totp.label)
        assertEquals(OtpAlgorithm.SHA1, totp.algorithm)
        val hotp =
            OtpAuthUri.parse(
                "otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&counter=42&digits=8&algorithm=SHA512",
            )
        assertEquals(OtpType.HOTP, hotp.type)
        assertEquals(42L, hotp.counter)
        assertEquals(8, hotp.digits)
        assertEquals(OtpAlgorithm.SHA512, hotp.algorithm)
    }

    @Test
    fun `Ente quirks - plus spaces, Algorithm prefix, codeDisplay tags, issuer leaking period`() {
        val p =
            OtpAuthUri.parse(
                "otpauth://totp/My Bank:me?algorithm=Algorithm.sha256&digits=6&issuer=My+Bankperiod=30" +
                    "&period=30&secret=JBSWY3DPEHPK3PXP" +
                    "&codeDisplay=%7B%22pinned%22%3Afalse%2C%22tags%22%3A%5B%22Work%22%2C%22Money%22%5D%7D",
            )
        assertEquals("My Bank", p.issuer)
        assertEquals("me", p.label)
        assertEquals(OtpAlgorithm.SHA256, p.algorithm)
        assertEquals(listOf("Work", "Money"), p.tags)
    }

    @Test
    fun `Steam by host and by encoder`() {
        val a = OtpAuthUri.parse("otpauth://steam/Steam:gamer?secret=JBSWY3DPEHPK3PXP")
        val b = OtpAuthUri.parse("otpauth://totp/Steam:gamer?secret=JBSWY3DPEHPK3PXP&encoder=steam&digits=6")
        assertEquals(OtpType.STEAM, a.type)
        assertEquals(OtpType.STEAM, b.type)
        assertEquals(OtpParams.STEAM_DIGITS, b.digits)
    }

    @Test
    fun `rejections never echo the secret`() {
        val secret = "JBSWY3DPEHPK3PX1"
        val e = assertThrows<OtpUriException> { OtpAuthUri.parse("otpauth://totp/x?secret=$secret") }
        assertFalse(e.message!!.contains(secret))
        assertThrows<OtpUriException> { OtpAuthUri.parse("https://example.com") }
        assertThrows<OtpUriException> { OtpAuthUri.parse("otpauth://totp/x?issuer=a") }
        assertThrows<OtpUriException> { OtpAuthUri.parse("otpauth://xotp/x?secret=JBSWY3DPEHPK3PXP") }
        assertThrows<OtpUriException> { OtpAuthUri.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12") }
        assertThrows<OtpUriException> { OtpAuthUri.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5") }
        assertThrows<OtpUriException> { OtpAuthUri.parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=abc") }
    }

    @Test
    fun `format round-trips`() {
        val p =
            OtpParams(
                OtpType.HOTP,
                "12345678901234567890".toByteArray(),
                OtpAlgorithm.SHA256,
                8,
                counter = 9,
                issuer = "Ex ample",
                label = "ünï@x",
            )
        val parsed = OtpAuthUri.parse(OtpAuthUri.format(p))
        assertEquals(p.copy(tags = emptyList()), parsed)
        val steam = OtpParams(OtpType.STEAM, "abc".toByteArray(), digits = 5, label = "g")
        assertEquals(steam, OtpAuthUri.parse(OtpAuthUri.format(steam)))
    }

    @Test
    fun `toString redacts`() {
        val p = OtpAuthUri.parse("otpauth://totp/Secretive:me?secret=JBSWY3DPEHPK3PXP")
        assertFalse(p.toString().contains("Secretive"))
        assertFalse(p.toString().contains("JBSWY3DPEHPK3PXP"))
    }
}
