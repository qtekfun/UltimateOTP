// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.security.MessageDigest

class CryptoRoundTripTest {
    private val cheap = listOf(2L to (16L shl 20))

    @ParameterizedTest
    @ValueSource(ints = [0, 1, 63, 64, 65, 200])
    fun `export round-trips at chunk boundaries`(size: Int) {
        val plain = ByteArray(size) { it.toByte() }
        val file = ExportFile.write(plain, "pässword", cheap, chunkSize = 64)
        assertTrue(ExportFile.isExport(file))
        assertArrayEquals(plain, ExportFile.read(file, "pässword")) // NFD input, NFC-normalized
    }

    @Test
    fun `KDF ladder falls back and fails below its last rung`() {
        // Above crypto_pwhash_MEMLIMIT_MAX (4 TiB on 64-bit): libsodium refuses without allocating.
        val impossible = 1L shl 43
        val (params, key) = PasswordKdf.deriveNew("x", listOf(4L to impossible, 2L to (16L shl 20)))
        assertEquals(16L shl 20, params.memLimit)
        assertEquals(32, key.size)
        assertThrows<CryptoException.KdfFailed> { PasswordKdf.deriveNew("x", listOf(1L to impossible)) }
        assertThrows<CryptoException.InvalidFormat> { PasswordKdf.derive("x", KdfParams(1, 1L shl 31, ByteArray(16))) }
    }

    @Test
    fun `ladder starts at the rung that fits in free memory`() {
        val gib = 1L shl 30
        assertEquals(3, PasswordKdf.ladderFor(8 * gib).size)
        assertEquals(512L shl 20, PasswordKdf.ladderFor(gib).first().second)
        assertEquals(listOf(PasswordKdf.SENSITIVE_LADDER.last()), PasswordKdf.ladderFor(1L shl 20))
    }

    @Test
    fun `paranoid bundle has no password path`() {
        val vk = Sodium.random(32)
        val rk = RecoveryKey.generate()
        val bundle = VaultKeyWraps.bundle(vk, 1, VaultKeyWraps.recoveryKek(rk), null, null)
        assertNull(bundle.passwordWrap)
        assertArrayEquals(vk, VaultKeyWraps.openWithRecoveryKey(rk, bundle.recoveryWrap, 1))
    }

    @Test
    fun `full bundle opens with the password`() {
        val vk = Sodium.random(32)
        val rk = RecoveryKey.generate()
        val (params, kek) = PasswordKdf.deriveNew("hunter2", cheap)
        val bundle = VaultKeyWraps.bundle(vk, 3, VaultKeyWraps.recoveryKek(rk), kek, params)
        val opened = VaultKeyWraps.openWithPassword("hunter2", bundle.passwordWrap!!, bundle.passwordKdf!!, 3)
        assertArrayEquals(vk, opened.vaultKey)
        assertArrayEquals(VaultKeyWraps.recoveryKek(rk), opened.recoveryKek)
        assertThrows<CryptoException.AuthenticationFailed> {
            VaultKeyWraps.openWithPassword("hunter3", bundle.passwordWrap, bundle.passwordKdf, 3)
        }
        assertEquals(24, RecoveryKey.toWords(rk).size)
        assertArrayEquals(rk, RecoveryKey.fromWords(RecoveryKey.toWords(rk).joinToString(", ").uppercase()))
    }

    @Test
    fun `device keys survive the Keystore export`() {
        val keys = DeviceKeys.generate()
        val again = DeviceKeys.fromSecrets(keys.exportSecrets())
        assertArrayEquals(keys.ed25519Public, again.ed25519Public)
        assertArrayEquals(keys.x25519Public, again.x25519Public)
        val sig = again.sign("m".toByteArray())
        assertTrue(Ed25519.verify(keys.ed25519Public, "m".toByteArray(), sig))
        assertFalse(Ed25519.verify(keys.ed25519Public, "n".toByteArray(), sig))
    }

    @Test
    fun `base64url is canonical`() {
        assertEquals("AQID", B64u.encode(byteArrayOf(1, 2, 3)))
        assertThrows<CryptoException.InvalidFormat> { B64u.decode("AQID=") }
        assertThrows<CryptoException.InvalidFormat> { B64u.decode("AQ+D") }
        assertThrows<CryptoException.InvalidFormat> { B64u.decode("AR") } // non-zero trailing bits
        assertThrows<CryptoException.InvalidFormat> { B64u.decode("A") }
    }

    @Test
    fun `bundled BIP-39 list is the official one`() {
        val digest = MessageDigest.getInstance("SHA-256")
        val text = Bip39::class.java.getResourceAsStream("bip39-english.txt")!!.readBytes()
        val hex = digest.digest(text).joinToString("") { "%02x".format(it) }
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hex)
        assertEquals("abandon", Bip39.encode(ByteArray(32)).first())
        assertEquals("art", Bip39.encode(ByteArray(32)).last())
    }
}
