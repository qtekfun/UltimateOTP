// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class Base32Test {
    /** RFC 4648 §10 (without padding on output). */
    @ParameterizedTest
    @CsvSource("f, MY", "fo, MZXQ", "foo, MZXW6", "foob, MZXW6YQ", "fooba, MZXW6YTB", "foobar, MZXW6YTBOI")
    fun `RFC 4648 vectors`(
        plain: String,
        encoded: String,
    ) {
        assertEquals(encoded, Base32.encode(plain.toByteArray()))
        assertArrayEquals(plain.toByteArray(), Base32.decode(encoded))
    }

    @Test
    fun `decoding is lenient with what people paste`() {
        assertArrayEquals("foobar".toByteArray(), Base32.decode("mzxw 6ytb-oi======"))
    }

    @Test
    fun `invalid characters and empty input are rejected`() {
        assertThrows<IllegalArgumentException> { Base32.decode("MZXW1") }
        assertThrows<IllegalArgumentException> { Base32.decode("  ") }
        assertFalse(Base32.isValid("not base32!"))
        assertTrue(Base32.isValid("JBSWY3DPEHPK3PXP"))
    }
}
