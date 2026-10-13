// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.math.BigInteger

class SrpTest {
    private val srp: JsonObject =
        Json
            .parseToJsonElement(File(System.getProperty("uotp.vectors")).readText())
            .jsonObject
            .getValue("srp")
            .jsonObject

    private fun JsonObject.str(name: String): String = getValue(name).jsonPrimitive.content

    private fun unhex(s: String): ByteArray =
        BigInteger(s, 16).toByteArray().let {
            if (it[0] == 0.toByte() &&
                it.size > 1
            ) {
                it.copyOfRange(1, it.size)
            } else {
                it
            }
        }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `RFC 5054 Appendix B arithmetic`() {
        val t = srp.getValue("rfc5054_appendix_b").jsonObject
        val group =
            SrpGroup(
                BigInteger(t.str("N"), 16),
                BigInteger.valueOf(
                    t
                        .getValue("g")
                        .jsonPrimitive.int
                        .toLong(),
                ),
                "SHA-1",
            )
        assertEquals(BigInteger(t.str("k"), 16), group.k)
        val x = group.x(t.str("I").toByteArray(), t.str("P").toByteArray(), unhex(t.str("s")))
        assertEquals(BigInteger(t.str("x"), 16), x)
        assertEquals(BigInteger(t.str("v"), 16), group.verifier(x))
        val session = Srp.startRaw(group, t.str("I").toByteArray(), t.str("P").toByteArray(), unhex(t.str("s")), unhex(t.str("a")))
        assertEquals(BigInteger(t.str("A"), 16), BigInteger(1, session.publicA))
    }

    @Test
    fun `UltimateOTP SRP vector`() {
        val kek = unhex(srp.str("kek_pw_hex"))
        assertEquals(srp.str("login_subkey_hex"), hex(Srp.loginSubkey(kek)))
        val salt = unhex(srp.str("srp_salt_hex"))
        val setup = Srp.setup(kek, srp.str("srp_user_id"), salt)
        assertEquals(srp.str("verifier_b64u"), B64u.encode(setup.verifier))
        val session = Srp.start(kek, srp.str("srp_user_id"), salt, privateA = unhex(srp.str("a_hex")))
        assertEquals(srp.str("A_b64u"), B64u.encode(session.publicA))
        val m1 = session.proof(B64u.decode(srp.str("B_b64u")))
        assertEquals(srp.str("M1_b64u"), B64u.encode(m1))
        assertTrue(session.verifyServer(B64u.decode(srp.str("M2_b64u"))))
        assertFalse(session.verifyServer(ByteArray(32)))
    }

    @Test
    fun `degenerate server values are refused`() {
        val session = Srp.start(ByteArray(32), "id", ByteArray(16))
        assertThrows<CryptoException.AuthenticationFailed> { session.proof(ByteArray(512)) }
        assertThrows<CryptoException.AuthenticationFailed> { session.proof(SrpGroup.RFC5054_4096.pad(SrpGroup.RFC5054_4096.n)) }
        assertArrayEquals(ByteArray(0), ByteArray(0))
    }
}
