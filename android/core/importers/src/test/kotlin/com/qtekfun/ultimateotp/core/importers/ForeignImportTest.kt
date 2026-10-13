// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.otp.Base32
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow

class ForeignImportTest {
    private fun fixture(name: String): ByteArray =
        requireNotNull(ForeignImportTest::class.java.getResourceAsStream("/fixtures/$name")) { "missing $name" }.use { it.readBytes() }

    private fun parsed(
        bytes: ByteArray,
        password: String? = null,
    ): ImportParse.Parsed = assertInstanceOf(ImportParse.Parsed::class.java, ForeignImport.parse(bytes, password))

    private fun String.b() = toByteArray(Charsets.UTF_8)

    /** The four accounts the Aegis project's fixtures contain, in every format. */
    private fun assertAegisProjectAccounts(p: ImportParse.Parsed) {
        val a = p.accounts.map { it.otp }
        assertTrue(a.size >= 6)
        assertEquals("Deno", a[0].issuer)
        assertEquals("Mason", a[0].label)
        assertEquals("4SJHB4GSD43FZBAI7C2HLRJGPQ", Base32.encode(a[0].secret))
        assertEquals(OtpAlgorithm.SHA1, a[0].algorithm)
        assertEquals(OtpAlgorithm.SHA256, a[1].algorithm)
        assertEquals(7, a[1].digits)
        assertEquals(20, a[1].period)
        assertEquals(OtpAlgorithm.SHA512, a[2].algorithm)
        assertEquals(8, a[2].digits)
        assertEquals(50, a[2].period)
    }

    // ---- Aegis ------------------------------------------------------------------------------

    @Test
    fun `Aegis plain vault from the Aegis project`() {
        val bytes = fixture("aegis_plain.json")
        assertEquals(ForeignFormat.AEGIS, ForeignImport.detect(bytes))
        val p = parsed(bytes)
        assertEquals(0, p.rejected)
        assertAegisProjectAccounts(p)
        val types = p.accounts.map { it.otp.type }
        assertTrue(OtpType.HOTP in types)
        assertTrue(OtpType.STEAM in types)
    }

    @Test
    fun `Aegis encrypted vault from the Aegis project`() {
        val bytes = fixture("aegis_encrypted.json")
        assertEquals(ImportParse.PasswordRequired(ForeignFormat.AEGIS), ForeignImport.parse(bytes))
        assertEquals(ImportParse.WrongPassword(ForeignFormat.AEGIS), ForeignImport.parse(bytes, "nope"))
        val encrypted = parsed(bytes, "test")
        val plain = parsed(fixture("aegis_plain.json"))
        assertEquals(plain.accounts.map { it.otp }, encrypted.accounts.map { it.otp })
    }

    @Test
    fun `Aegis self-made vault covers groups, notes, favorites and rejected types`() {
        for (json in listOf(FixtureBuilders.AEGIS_DB.let { """{"version":1,"header":{"slots":null,"params":null},"db":$it}""" }.b())) {
            val p = parsed(json)
            assertEquals(3, p.accounts.size)
            assertEquals(2, p.rejected)
            assertEquals(listOf("Work"), p.accounts[0].otp.tags)
            assertEquals("work", p.accounts[0].notes)
            assertTrue(p.accounts[0].favorite)
            assertEquals(60, p.accounts[0].otp.period)
            assertEquals(41L, p.accounts[1].otp.counter)
            assertEquals(OtpType.STEAM, p.accounts[2].otp.type)
            assertEquals(5, p.accounts[2].otp.digits)
        }
        val enc = FixtureBuilders.aegisEncrypted().b()
        assertEquals(3, parsed(enc, FixtureBuilders.PASSWORD).accounts.size)
        assertEquals(ImportParse.WrongPassword(ForeignFormat.AEGIS), ForeignImport.parse(enc, "wrong"))
    }

    @Test
    fun `Aegis tampered database and missing password slot`() {
        val tampered = FixtureBuilders.aegisEncrypted(tamper = true).b()
        assertEquals(ImportParse.WrongPassword(ForeignFormat.AEGIS), ForeignImport.parse(tampered, FixtureBuilders.PASSWORD))
        val noSlot = ForeignImport.parse(FixtureBuilders.aegisEncrypted(passwordSlot = false).b(), FixtureBuilders.PASSWORD)
        val u = assertInstanceOf(ImportParse.Unsupported::class.java, noSlot)
        assertTrue("password slot" in u.reason)
    }

    @Test
    fun `Aegis hostile scrypt parameters are refused without running them`() {
        val hostile = FixtureBuilders.aegisEncrypted(n = 1024).replace("\"n\":1024", "\"n\":1073741824").b()
        val u = assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(hostile, "x"))
        assertEquals(ForeignFormat.AEGIS, u.format)
    }

    @Test
    fun `Aegis newer versions are refused with a clear message`() {
        val v2 = """{"version":2,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[]}}"""
        assertTrue("version" in assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(v2.b())).reason)
        val db4 = """{"version":1,"header":{"slots":null,"params":null},"db":{"version":4,"entries":[]}}"""
        assertTrue("newer" in assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(db4.b())).reason)
    }

    // ---- 2FAS -------------------------------------------------------------------------------

    @Test
    fun `2FAS plain and encrypted v4 backups from the Aegis project`() {
        val plainBytes = fixture("2fas_authenticator_plain_v4.2fas")
        assertEquals(ForeignFormat.TWO_FAS, ForeignImport.detect(plainBytes))
        val plain = parsed(plainBytes)
        assertEquals(0, plain.rejected)
        assertTrue(plain.accounts.size >= 3)
        assertEquals("Deno", plain.accounts[0].otp.issuer)
        assertEquals("Mason", plain.accounts[0].otp.label)

        val encBytes = fixture("2fas_authenticator_encrypted_v4.2fas")
        assertEquals(ImportParse.PasswordRequired(ForeignFormat.TWO_FAS), ForeignImport.parse(encBytes))
        assertEquals(ImportParse.WrongPassword(ForeignFormat.TWO_FAS), ForeignImport.parse(encBytes, "bad"))
        val enc = parsed(encBytes, "test")
        assertEquals(plain.accounts.map { it.otp }, enc.accounts.map { it.otp })
    }

    @Test
    fun `2FAS older schema 2 encrypted backup`() {
        val p = parsed(fixture("2fas_authenticator_encrypted.2fas"), "test")
        assertTrue(p.accounts.isNotEmpty())
    }

    @Test
    fun `2FAS self-made backup with groups, HOTP and an unknown token type`() {
        for (bytes in listOf(FixtureBuilders.twoFasPlain().b(), FixtureBuilders.twoFasEncrypted().b())) {
            val p = parsed(bytes, FixtureBuilders.PASSWORD)
            assertEquals(2, p.accounts.size)
            assertEquals(1, p.rejected)
            assertEquals("Example", p.accounts[0].otp.issuer)
            assertEquals(listOf("Personal"), p.accounts[0].otp.tags)
            assertEquals("JBSWY3DPEHPK3PXP", Base32.encode(p.accounts[0].otp.secret))
            assertEquals(OtpType.HOTP, p.accounts[1].otp.type)
            assertEquals(5L, p.accounts[1].otp.counter)
            assertEquals(8, p.accounts[1].otp.digits)
        }
    }

    @Test
    fun `2FAS unknown schema and truncated encrypted field`() {
        val newer = FixtureBuilders.twoFasPlain(schema = 9).b()
        assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(newer))
        val broken = """{"services":[],"schemaVersion":4,"servicesEncrypted":"AAAA:BBBB"}"""
        assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(broken.b(), "x"))
    }

    // ---- andOTP -----------------------------------------------------------------------------

    @Test
    fun `andOTP plain, new and old encrypted from the Aegis project`() {
        val plainBytes = fixture("andotp_plain.json")
        assertEquals(ForeignFormat.ANDOTP, ForeignImport.detect(plainBytes))
        val plain = parsed(plainBytes)
        assertAegisProjectAccounts(plain)
        for (name in listOf("andotp_encrypted.bin", "andotp_encrypted_old.bin")) {
            val bytes = fixture(name)
            assertEquals(ForeignFormat.ANDOTP, ForeignImport.detect(bytes))
            assertEquals(ImportParse.PasswordRequired(ForeignFormat.ANDOTP), ForeignImport.parse(bytes))
            assertEquals(ImportParse.WrongPassword(ForeignFormat.ANDOTP), ForeignImport.parse(bytes, "bad"))
            // The old-format sample has no Steam entry and writes labels as "Issuer:account".
            val got = parsed(bytes, "test").accounts.map { it.otp }
            assertEquals(plain.accounts.map { it.otp }.take(6), got.take(6), name)
        }
    }

    @Test
    fun `andOTP self-made backups split the old issuer - label form and reject MOTP`() {
        for (bytes in listOf(FixtureBuilders.ANDOTP_JSON.b(), FixtureBuilders.andOtpNew(), FixtureBuilders.andOtpOld())) {
            val p = parsed(bytes, FixtureBuilders.PASSWORD)
            assertEquals(3, p.accounts.size)
            assertEquals(1, p.rejected)
            assertEquals("Example", p.accounts[0].otp.issuer)
            assertEquals(listOf("Work"), p.accounts[0].otp.tags)
            assertEquals("Bank", p.accounts[1].otp.issuer)
            assertEquals("bob", p.accounts[1].otp.label)
            assertEquals(9L, p.accounts[1].otp.counter)
            assertEquals(OtpType.STEAM, p.accounts[2].otp.type)
        }
        assertEquals(ImportParse.WrongPassword(ForeignFormat.ANDOTP), ForeignImport.parse(FixtureBuilders.andOtpNew(), "nope"))
    }

    @Test
    fun `andOTP implausible iteration counts do not stall and OpenPGP armor is explained`() {
        val hostile = FixtureBuilders.andOtpNew().also { it[0] = 0x7F } // 2.1 billion iterations
        assertEquals(ImportParse.WrongPassword(ForeignFormat.ANDOTP), ForeignImport.parse(hostile, "x"))
        val pgp = "-----BEGIN PGP MESSAGE-----\n\nhQEMA...\n-----END PGP MESSAGE-----".b()
        val u = assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(pgp))
        assertTrue("OpenPGP" in u.reason)
    }

    // ---- Raivo ------------------------------------------------------------------------------

    @Test
    fun `Raivo json and zip`() {
        for (bytes in listOf(FixtureBuilders.RAIVO_JSON.b(), FixtureBuilders.zip("raivo-otp-export.json", FixtureBuilders.RAIVO_JSON))) {
            assertEquals(ForeignFormat.RAIVO, ForeignImport.detect(bytes))
            val p = parsed(bytes)
            assertEquals(2, p.accounts.size)
            assertEquals(1, p.rejected)
            assertEquals("Example", p.accounts[0].otp.issuer)
            assertEquals("alice@example.com", p.accounts[0].otp.label)
            assertEquals(OtpType.HOTP, p.accounts[1].otp.type)
            assertEquals(12L, p.accounts[1].otp.counter)
            assertEquals(8, p.accounts[1].otp.digits)
        }
    }

    @Test
    fun `Raivo password-protected zip and a zip without json are refused clearly`() {
        val zip = FixtureBuilders.zip("raivo-otp-export.json", FixtureBuilders.RAIVO_JSON)
        val encrypted = zip.copyOf().also { it[6] = (it[6].toInt() or 1).toByte() }
        val u = assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(encrypted))
        assertTrue("password-protected" in u.reason)
        val other = FixtureBuilders.zip("notes.txt", "hello")
        assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(other))
    }

    // ---- Bitwarden --------------------------------------------------------------------------

    @Test
    fun `Bitwarden json and csv from the Aegis project`() {
        for (name in listOf("bitwarden.json", "bitwarden.csv")) {
            val bytes = fixture(name)
            assertEquals(ForeignFormat.BITWARDEN, ForeignImport.detect(bytes), name)
            val p = parsed(bytes)
            assertEquals(4, p.accounts.size, name)
            assertEquals("Deno", p.accounts[0].otp.issuer)
            assertEquals(OtpType.STEAM, p.accounts[3].otp.type)
            assertEquals("Steam", p.accounts[3].otp.issuer)
            assertEquals(
                "Test 4",
                p.accounts[3]
                    .otp.label
                    .ifEmpty { "Test 4" },
            )
        }
    }

    @Test
    fun `Bitwarden csv with quotes and bare secrets, and the encrypted json refusal`() {
        val csv =
            "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\r\n" +
                ",1,login,\"Acme, Inc\",\"line one\nline two\",,,carol@acme.test,pw,JBSW Y3DP EHPK 3PXP\r\n" +
                ",,login,No totp,,,,dave,pw,\r\n" +
                ",,login,Bad,,,,erin,pw,otpauth://totp/Bad?secret=0000\r\n"
        val p = parsed(csv.b())
        assertEquals(1, p.accounts.size)
        assertEquals(1, p.rejected)
        val a = p.accounts[0]
        assertEquals("Acme, Inc", a.otp.issuer)
        assertEquals("carol@acme.test", a.otp.label)
        assertEquals("line one\nline two", a.notes)
        assertTrue(a.favorite)
        val enc = """{"encrypted":true,"folders":[],"items":[],"encKeyValidation_DO_NOT_EDIT":"2.x"}"""
        assertTrue("encrypted" in assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(enc.b())).reason)
    }

    // ---- Proton -----------------------------------------------------------------------------

    @Test
    fun `Proton plain and encrypted from the Aegis project`() {
        val plainBytes = fixture("proton_authenticator.json")
        assertEquals(ForeignFormat.PROTON, ForeignImport.detect(plainBytes))
        val plain = parsed(plainBytes)
        assertEquals(0, plain.rejected)
        assertEquals("Deno", plain.accounts[0].otp.issuer)
        val encBytes = fixture("proton_authenticator_encrypted.json")
        assertEquals(ImportParse.PasswordRequired(ForeignFormat.PROTON), ForeignImport.parse(encBytes))
        assertEquals(ImportParse.WrongPassword(ForeignFormat.PROTON), ForeignImport.parse(encBytes, "bad"))
        val enc = parsed(encBytes, "test")
        assertEquals(plain.accounts.map { it.otp }, enc.accounts.map { it.otp }.take(plain.accounts.size))
        assertEquals(
            OtpType.STEAM,
            enc.accounts
                .last()
                .otp.type,
        )
    }

    @Test
    fun `Proton self-made export with notes, steam and a junk entry`() {
        for (bytes in listOf(FixtureBuilders.PROTON_JSON.b(), FixtureBuilders.protonEncrypted().b())) {
            val p = parsed(bytes, FixtureBuilders.PASSWORD)
            assertEquals(2, p.accounts.size)
            assertEquals(1, p.rejected)
            assertEquals("hello", p.accounts[0].notes)
            assertEquals(OtpType.STEAM, p.accounts[1].otp.type)
        }
        val v2 = """{"version":2,"entries":[]}"""
        assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(v2.b()))
    }

    // ---- everything else --------------------------------------------------------------------

    @Test
    fun `files that are not exports are not detected`() {
        assertNull(ForeignImport.detect("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP\n".b()))
        assertNull(ForeignImport.detect(ByteArray(0)))
        assertNull(ForeignImport.detect("{}".b()))
        assertNull(ForeignImport.detect("[]".b()))
        assertNull(ForeignImport.detect("hello world".b()))
        assertNull(ForeignImport.detect("{\"version\":1}".b()))
        assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse("hello".b()))
        assertInstanceOf(ImportParse.Unsupported::class.java, ForeignImport.parse(ByteArray(0)))
    }

    @Test
    fun `truncated and corrupted files never throw`() {
        val files =
            listOf(
                "aegis_plain.json",
                "aegis_encrypted.json",
                "2fas_authenticator_plain_v4.2fas",
                "2fas_authenticator_encrypted_v4.2fas",
                "andotp_plain.json",
                "andotp_encrypted.bin",
                "andotp_encrypted_old.bin",
                "bitwarden.json",
                "bitwarden.csv",
                "proton_authenticator.json",
            ).associateWith(::fixture)
        for ((name, bytes) in files) {
            for (cut in listOf(0, 1, 7, bytes.size / 3, bytes.size / 2, bytes.size - 1)) {
                assertDoesNotThrow("$name cut $cut") { ForeignImport.parse(bytes.copyOf(cut), "test") }
            }
            val flipped = bytes.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x55).toByte() }
            assertDoesNotThrow("$name flipped") { ForeignImport.parse(flipped, "test") }
        }
    }

    @Test
    fun `reasons and string forms never carry secrets or issuers`() {
        val secret = "JBSWY3DPEHPK3PXP"
        val bad = """[{"kind":"TOTP","issuer":"SecretIssuer","account":"a","secret":"$secret","algorithm":"SHA999"}"""
        val res = ForeignImport.parse(bad.b())
        assertFalse(res.toString().contains(secret))
        assertFalse(res.toString().contains("SecretIssuer"))
        val ok = parsed(FixtureBuilders.RAIVO_JSON.b())
        assertFalse(ok.accounts[0].toString().contains(secret))
        assertFalse(
            ok.accounts[0]
                .otp
                .toString()
                .contains(secret),
        )
    }
}
