// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.util.Base64
import java.util.UUID

/** Every vector of docs/crypto-vectors/vectors.json (generated with PyNaCl, crypto-format.md §13). */
class CryptoVectorsTest {
    private val v: JsonObject = Json.parseToJsonElement(File(System.getProperty("uotp.vectors")).readText()).jsonObject

    private fun JsonObject.obj(name: String): JsonObject = getValue(name).jsonObject

    private fun JsonObject.str(name: String): String = getValue(name).jsonPrimitive.content

    private fun JsonObject.hex(name: String): ByteArray = unhex(str(name))

    private fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `password KDF, including a non-ASCII password (bindings bug workaround)`() {
        for (case in v.getValue("password_kdf").jsonArray.map { it.jsonObject }) {
            val password = case.str("password")
            assertArrayEquals(case.hex("password_nfc_utf8_hex"), PasswordKdf.passwordBytes(password))
            val params =
                KdfParams(
                    case.getValue("opslimit").jsonPrimitive.long,
                    case.getValue("memlimit").jsonPrimitive.long,
                    case.hex("salt_hex"),
                )
            assertArrayEquals(case.hex("kek_hex"), PasswordKdf.derive(password, params))
        }
    }

    @Test
    fun `key wraps and their API encoding`() {
        val w = v.obj("wraps")
        val vk = w.hex("vk_hex")
        val kekPw = w.hex("kek_pw_hex")
        val params = KdfParams.decode(B64u.decode(w.str("password_kdf_b64u")))
        val kekRk = VaultKeyWraps.recoveryKek(w.hex("recovery_key_hex"))
        assertArrayEquals(w.hex("kek_rk_hex"), kekRk)
        val pw = KeyWrap.wrap(WrapKind.PASSWORD, kekPw, vk, 1, params, w.obj("password_wrap").hex("nonce_hex"))
        assertArrayEquals(w.obj("password_wrap").hex("wrap_hex"), pw)
        val rk = KeyWrap.wrap(WrapKind.RECOVERY, kekRk, vk, 1, null, w.obj("recovery_wrap").hex("nonce_hex"))
        assertArrayEquals(w.obj("recovery_wrap").hex("wrap_hex"), rk)
        val rkek = KeyWrap.wrap(WrapKind.RECOVERY_KEK, kekPw, kekRk, 0, params, w.obj("recovery_kek_wrap").hex("nonce_hex"))
        assertArrayEquals(w.obj("recovery_kek_wrap").hex("wrap_hex"), rkek)

        val opened = VaultKeyWraps.openWithKek(kekPw, w.str("api_password_wrap_b64u"), params, 1)
        assertArrayEquals(vk, opened.vaultKey)
        assertArrayEquals(kekRk, opened.recoveryKek)
        val recovered =
            VaultKeyWraps.openWithRecoveryKey(
                RecoveryKey.fromWords(w.getValue("recovery_words").jsonArray.joinToString(" ") { it.jsonPrimitive.content }),
                w.obj("recovery_wrap").str("api_b64u"),
                1,
            )
        assertArrayEquals(vk, recovered)
        assertThrows<CryptoException.AuthenticationFailed> {
            VaultKeyWraps.openWithKek(kekPw, w.str("api_password_wrap_b64u"), params, 2)
        }
    }

    @Test
    fun `recovery words`() {
        val w = v.obj("wraps")
        val words = w.getValue("recovery_words").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(words, RecoveryKey.toWords(w.hex("recovery_key_hex")))
        assertThrows<CryptoException.InvalidFormat> { RecoveryKey.fromWords((words.dropLast(1) + "abandon").joinToString(" ")) }
    }

    @Test
    fun `item blob`() {
        val i = v.obj("item")
        val itemKey = ItemCipher.itemKey(i.hex("vk_hex"))
        assertArrayEquals(i.hex("k_item_hex"), itemKey)
        val binding = ItemBinding(i.str("account_id"), UUID.fromString(i.str("item_id")), 3, 1)
        assertArrayEquals(i.hex("ad_hex"), binding.ad())
        assertArrayEquals(i.hex("local_ad_hex"), binding.copy(accountId = "", itemVersion = 1).ad())
        val blob = ItemCipher.encrypt(itemKey, binding, i.str("plaintext").toByteArray(), i.hex("nonce_hex"))
        assertArrayEquals(i.hex("blob_hex"), blob)
        assertEquals(i.str("blob_b64u"), B64u.encode(blob))
        assertEquals(i.str("plaintext"), String(ItemCipher.decrypt(itemKey, binding, blob)))
        assertEquals(1L, ItemCipher.keyEpochOf(blob))
        // Moving the blob to another item, version or account fails.
        for (other in listOf(binding.copy(itemVersion = 4), binding.copy(itemId = UUID.randomUUID()), binding.copy(accountId = "acc_x"))) {
            assertThrows<CryptoException.AuthenticationFailed> { ItemCipher.decrypt(itemKey, other, blob) }
        }
    }

    private fun device(o: JsonObject): DeviceKeys = DeviceKeys.fromSeed(o.hex("sign_seed_hex"), o.hex("x25519_sk_hex"))

    @Test
    fun `devices, certificate and SAS`() {
        val d = v.obj("devices")
        val a = device(d.obj("a"))
        val b = device(d.obj("b"))
        assertEquals(d.obj("a").str("ed25519_b64u"), a.ed25519PublicB64u)
        assertEquals(d.obj("b").str("x25519_b64u"), b.x25519PublicB64u)
        val cert = Statements.device(d.str("account_id"), d.obj("b").str("device_id"), b.ed25519PublicB64u, b.x25519PublicB64u)
        assertEquals(d.obj("device_certificate_b").str("message"), String(cert))
        assertEquals(d.obj("device_certificate_b").str("signature_by_a_b64u"), a.signB64u(cert))
        assertTrue(Ed25519.verifyB64u(a.ed25519PublicB64u, cert, a.signB64u(cert)))
        assertFalse(Ed25519.verifyB64u(b.ed25519PublicB64u, cert, a.signB64u(cert)))
        assertEquals(
            d.getValue("sas_words").jsonArray.map { it.jsonPrimitive.content },
            Sas.words(a.ed25519Public, b.ed25519Public, b.x25519Public),
        )
    }

    @Test
    fun `head manifest and signature`() {
        val h = v.obj("head")
        val a = device(v.obj("devices").obj("a"))
        val live =
            h.getValue("live_items").jsonArray.map { it.jsonObject }.map {
                Statements.ManifestEntry(it.str("item_id"), it.getValue("version").jsonPrimitive.long, B64u.decode(it.str("blob_b64u")))
            }
        val manifest = Statements.manifest(live.reversed())
        assertEquals(h.str("manifest"), String(manifest))
        assertEquals(h.str("empty_manifest_sha256_b64u"), sha256B64u(Statements.manifest(emptyList())))
        val msg = Statements.head(h.str("account_id"), 42, 1, h.str("signed_by"), manifest)
        assertEquals(h.str("message"), String(msg))
        assertEquals(h.str("signature_by_a_b64u"), a.signB64u(msg))
    }

    @Test
    fun `request signature`() {
        val r = v.obj("request_signature")
        val a = device(v.obj("devices").obj("a"))
        val msg =
            Statements.request(
                r.str("method").lowercase(),
                r.str("target"),
                r.str("device"),
                r.str("timestamp").toLong(),
                r.str("nonce"),
                r.str("body").toByteArray(),
            )
        assertEquals(r.str("message"), String(msg))
        assertEquals(r.str("signature_by_a_b64u"), a.signB64u(msg))
    }

    @Test
    fun `sealed vault key opens, binds account and epoch, and round-trips`() {
        val s = v.obj("sealed_vault_key")
        val d = v.obj("devices")
        val a = device(d.obj("a"))
        val b = device(d.obj("b"))
        val sealed = B64u.decode(s.str("sealed_b64u"))
        val accountId = d.str("account_id")
        val msg = Statements.seal(accountId, 1, d.obj("b").str("device_id"), sealed)
        assertEquals(s.str("message"), String(msg))
        assertTrue(Ed25519.verifyB64u(a.ed25519PublicB64u, msg, s.str("signature_by_a_b64u")))
        val vk = v.obj("wraps").hex("vk_hex")
        assertArrayEquals(vk, SealedVaultKey.open(b, sealed, 1, accountId))
        assertThrows<CryptoException.AuthenticationFailed> { SealedVaultKey.open(b, sealed, 2, accountId) }
        assertThrows<CryptoException.AuthenticationFailed> { SealedVaultKey.open(a, sealed, 1, accountId) }
        val mine = SealedVaultKey.seal(vk, 7, accountId, b.x25519Public)
        assertEquals(123, mine.size)
        assertArrayEquals(vk, SealedVaultKey.open(b, mine, 7, accountId))
    }

    @Test
    fun `export file written by PyNaCl`() {
        val e = v.obj("export")
        val file = Base64.getDecoder().decode(e.str("file_b64"))
        assertEquals(e.str("plaintext"), String(ExportFile.read(file, e.str("password"))))
        assertThrows<CryptoException.AuthenticationFailed> { ExportFile.read(file, "wrong") }
        // Cut inside the final chunk: its tag fails. Cut a whole final chunk: no TAG_FINAL, truncated.
        assertThrows<CryptoException.AuthenticationFailed> { ExportFile.read(file.copyOf(file.size - 20), e.str("password")) }
        val plainLen = e.str("plaintext").length
        val finalChunk = plainLen % 64 + 17
        assertThrows<CryptoException.InvalidFormat> { ExportFile.read(file.copyOf(file.size - finalChunk), e.str("password")) }
        // An extra byte lengthens the final chunk, whose tag then fails.
        assertThrows<CryptoException.AuthenticationFailed> { ExportFile.read(file + byteArrayOf(1), e.str("password")) }
        val tampered = file.copyOf().also { it[10] = (it[10] + 1).toByte() } // opslimit in the header
        assertThrows<CryptoException> { ExportFile.read(tampered, e.str("password")) }
        assertEquals(e.getValue("chunk_size").jsonPrimitive.int, 64)
    }

    @Test
    fun `Ente encrypted export`() {
        val e = v.obj("ente_encrypted_export")
        assertTrue(EnteExport.isEncryptedExport(e.str("file")))
        assertEquals(e.str("plaintext"), EnteExport.decrypt(e.str("file"), e.str("password")))
        assertThrows<CryptoException.AuthenticationFailed> { EnteExport.decrypt(e.str("file"), "nope") }
        assertFalse(EnteExport.isEncryptedExport("otpauth://totp/x?secret=AAAA"))
    }
}
