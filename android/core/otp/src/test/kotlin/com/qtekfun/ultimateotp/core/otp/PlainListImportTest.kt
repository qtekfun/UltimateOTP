// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class PlainListImportTest {
    @Test
    fun `Ente plain export with a bad line and a quoted line`() {
        val text =
            """
            otpauth://totp/Example:alice@example.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP
            not a uri
            "otpauth://hotp/Bank:bob?algorithm=SHA256&digits=8&issuer=Bank&secret=GEZDGNBVGY3TQOJQ&counter=7"

            otpauth://totp/Broken?secret=0000
            """.trimIndent()
        val result = PlainListImport.parse(text)
        assertEquals(2, result.accounts.size)
        assertEquals(2, result.rejected)
        assertEquals("Bank", result.accounts[1].issuer)
        assertEquals(7L, result.accounts[1].counter)
    }

    /** Payload built with a hand-written protobuf encoder (field numbers of Google's MigrationPayload). */
    @Test
    fun `Google Authenticator migration`() {
        val uri =
            "otpauth-migration://offline?data=" +
                "CjYKCkhlbGxvId6tvu8SGUV4YW1wbGU6YWxpY2VAZXhhbXBsZS5jb20aB0V4YW1wbGUgASgBMAIK" +
                "KwoUMTIzNDU2Nzg5MDEyMzQ1Njc4OTASBGLDs2IaBEJhbmsgAigCMAE4rAIQARgB"
        val accounts = PlainListImport.parse(uri).accounts
        assertEquals(2, accounts.size)
        val a = accounts[0]
        assertEquals(OtpType.TOTP, a.type)
        assertEquals("Example", a.issuer)
        assertEquals("alice@example.com", a.label)
        assertEquals("JBSWY3DPEHPK3PXP", Base32.encode(a.secret))
        val b = accounts[1]
        assertEquals(OtpType.HOTP, b.type)
        assertEquals(OtpAlgorithm.SHA256, b.algorithm)
        assertEquals(8, b.digits)
        assertEquals(300L, b.counter)
        assertEquals("bób", b.label)
        assertEquals("Bank", b.issuer)
    }

    @Test
    fun `malformed migration payloads are rejected`() {
        assertThrows<OtpUriException> { GoogleMigration.parse("otpauth-migration://offline?data=") }
        assertThrows<OtpUriException> { GoogleMigration.parse("otpauth-migration://offline?data=%%%") }
        assertThrows<OtpUriException> { GoogleMigration.parse("otpauth-migration://offline?data=CjYK") }
    }
}
