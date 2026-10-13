// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Known-answer tests for the KDFs used to read other apps' files (RFC 6070, RFC 7914). */
class ForeignKdfTest {
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun String.b() = toByteArray(Charsets.UTF_8)

    @Test
    fun `PBKDF2-HMAC-SHA1 RFC 6070`() {
        assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6", hex(Pbkdf2.derive(Pbkdf2.HMAC_SHA1, "password".b(), "salt".b(), 1, 20)))
        assertEquals("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", hex(Pbkdf2.derive(Pbkdf2.HMAC_SHA1, "password".b(), "salt".b(), 2, 20)))
        assertEquals(
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            hex(
                Pbkdf2.derive(
                    Pbkdf2.HMAC_SHA1,
                    "passwordPASSWORDpassword".b(),
                    "saltSALTsaltSALTsaltSALTsaltSALTsalt".b(),
                    4096,
                    25,
                ),
            ),
        )
    }

    @Test
    fun `PBKDF2-HMAC-SHA256 RFC 7914 section 11`() {
        assertEquals(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            hex(Pbkdf2.derive(Pbkdf2.HMAC_SHA256, "passwd".b(), "salt".b(), 1, 64)),
        )
    }

    @Test
    fun `scrypt RFC 7914 section 12`() {
        assertEquals(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442" +
                "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            hex(Scrypt.derive(ByteArray(0), ByteArray(0), 16, 1, 1, 64)),
        )
        assertEquals(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
                "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            hex(Scrypt.derive("password".b(), "NaCl".b(), 1024, 8, 16, 64)),
        )
        assertEquals(
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" +
                "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            hex(Scrypt.derive("pleaseletmein".b(), "SodiumChloride".b(), 16384, 8, 1, 64)),
        )
    }

    @Test
    fun `scrypt refuses parameters that would stall or exhaust the device`() {
        assertThrows<CryptoException.InvalidFormat> { Scrypt.derive(ByteArray(1), ByteArray(1), 3, 8, 1, 32) }
        assertThrows<CryptoException.InvalidFormat> { Scrypt.derive(ByteArray(1), ByteArray(1), 1 shl 25, 8, 1, 32) }
        assertThrows<CryptoException.InvalidFormat> { Scrypt.derive(ByteArray(1), ByteArray(1), 16, 8, 64, 32) }
    }
}
