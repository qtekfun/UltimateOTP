// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.sun.jna.NativeLong
import io.kotest.common.ExperimentalKotest
import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * The password KDF as a real phone will run it (crypto-format.md §4.1): which rung the memory
 * figure picks, that every rung is something the wire format and the server can carry and a
 * second implementation can reproduce, and that a device with a different ladder opens what
 * another wrote.
 *
 * What this cannot show: that the device has the memory. `ladderFor` trusts the number it is
 * given; the instrumented `KdfMaxStepTest` runs the maximum rung on an emulator.
 */
@OptIn(ExperimentalKotest::class)
class PasswordKdfLadderTest {
    private val mib = 1L shl 20
    private val gib = 1L shl 30
    private val ladder = PasswordKdf.SENSITIVE_LADDER
    private val strongest = ladder.first()
    private val weakest = ladder.last()

    // ---- the decision: which rungs does this much free memory allow --------------------------

    @Test
    fun `the ladder is sensitive, then equal total work at half the memory`() {
        assertEquals(listOf(4L to gib, 8L to 512 * mib, 16L to 256 * mib), ladder)
        // Work (passes x memory) stays equal, which is the point of halving memory and doubling passes.
        assertEquals(1, ladder.map { (ops, mem) -> ops * mem }.distinct().size)
    }

    @ParameterizedTest
    @ValueSource(longs = [Long.MIN_VALUE, -1, 0, 1, 255L * 1024 * 1024, 383L * 1024 * 1024])
    fun `unknown, negative and very low memory still gets exactly the last rung and never fewer`(available: Long) {
        // 0 is what `MemoryInfo.availMem` holds when ActivityManager gives no answer.
        assertEquals(listOf(weakest), PasswordKdf.ladderFor(available))
    }

    @Test
    fun `each rung needs one and a half times its memory free`() {
        // 256 MiB rung: 384 MiB. 512 MiB rung: 768 MiB. 1 GiB rung: 1536 MiB.
        assertEquals(listOf(weakest), PasswordKdf.ladderFor(384 * mib - 1))
        assertEquals(listOf(weakest), PasswordKdf.ladderFor(384 * mib))
        assertEquals(ladder.drop(1), PasswordKdf.ladderFor(768 * mib))
        assertEquals(listOf(weakest), PasswordKdf.ladderFor(768 * mib - 1))
        assertEquals(ladder.drop(1), PasswordKdf.ladderFor(1536 * mib - 1))
        assertEquals(ladder, PasswordKdf.ladderFor(1536 * mib))
        assertEquals(ladder, PasswordKdf.ladderFor(Long.MAX_VALUE))
    }

    @Test
    fun `for any figure the ladder is a non-empty tail of the full ladder, strongest first`(): Unit =
        runBlocking {
            checkAll(PropTestConfig(iterations = 2_000, seed = SEED), Arb.long()) { available ->
                val chosen = PasswordKdf.ladderFor(available)
                assertTrue(chosen.isNotEmpty())
                assertEquals(ladder.takeLast(chosen.size), chosen)
                if (available >= 1536 * mib) assertEquals(strongest, chosen.first())
                // The first rung fits with headroom, unless not even the last does (it is used anyway).
                if (available >= weakest.second * 3 / 2) assertTrue(chosen.first().second * 3 / 2 <= available)
            }
        }

    @Test
    fun `more free memory never selects a weaker first rung`(): Unit =
        runBlocking {
            checkAll(PropTestConfig(iterations = 1_000, seed = SEED), Arb.long(0L..8 * gib), Arb.long(0L..8 * gib)) { a, b ->
                val low = minOf(a, b)
                val high = maxOf(a, b)
                assertTrue(PasswordKdf.ladderFor(high).size >= PasswordKdf.ladderFor(low).size)
            }
        }

    // ---- representable: the wire format, the reader limits, the server's password_kdf ---------

    @Test
    fun `every rung is a 29-byte params block the reader limits accept, and round-trips`() {
        val salt = ByteArray(KdfParams.SALT_BYTES) { it.toByte() }
        for ((ops, mem) in ladder) {
            val block = KdfParams(ops, mem, salt).encode()
            assertEquals(KdfParams.ENCODED_BYTES, block.size) // the server accepts exactly 29 bytes (formats.py)
            assertEquals(KdfParams.ALG_ARGON2ID13, block[0].toInt())
            val back = KdfParams.decode(block).checkReaderLimits()
            assertEquals(ops, back.opsLimit)
            assertEquals(mem, back.memLimit)
            assertArrayEquals(salt, back.salt)
        }
    }

    @Test
    fun `the strongest rung is exactly the reader's upper memory bound, so it is never refused as absurd`() {
        assertEquals(KdfParams.MAX_MEM, strongest.second)
        assertTrue(ladder.all { (ops, mem) -> ops in KdfParams.MIN_OPS..KdfParams.MAX_OPS && mem in KdfParams.MIN_MEM..KdfParams.MAX_MEM })
        // One byte more is refused, so a ladder edit that raises the first rung fails loudly here.
        assertThrows<CryptoException.InvalidFormat> {
            KdfParams(strongest.first, strongest.second + 1, ByteArray(16)).checkReaderLimits()
        }
    }

    @Test
    fun `any reader-valid parameters survive the wire format`(): Unit =
        runBlocking {
            val salts = Arb.byteArray(Arb.int(16..16), Arb.byte())
            checkAll(
                PropTestConfig(iterations = 500, seed = SEED),
                Arb.long(KdfParams.MIN_OPS..KdfParams.MAX_OPS),
                Arb.long(KdfParams.MIN_MEM..KdfParams.MAX_MEM),
                salts,
            ) { ops, mem, salt ->
                val p = KdfParams(ops, mem, salt)
                assertEquals(p, KdfParams.decode(p.encode()).checkReaderLimits())
            }
        }

    // ---- 32-bit ABIs (armeabi-v7a, x86) -------------------------------------------------------

    /**
     * `crypto_pwhash(..., size_t memlimit, ...)`: the bindings pass a 64-bit integer, which on a
     * 32-bit ABI shifts every following argument (the reason PasswordKdf calls the function itself
     * with [NativeLong]). On a 32-bit ABI `NativeLong` is 4 bytes, so every memlimit the ladder can
     * produce must survive being narrowed to a signed 32-bit int unchanged.
     */
    @Test
    fun `every rung fits a 32-bit size_t and a signed 32-bit NativeLong`() {
        for ((_, mem) in ladder) {
            assertEquals(mem, mem.toInt().toLong(), "memlimit $mem is changed by a 32-bit size_t")
            assertTrue(mem.toInt() > 0)
            assertEquals(mem, NativeLong(mem).toLong())
        }
        assertTrue(KdfParams.MAX_MEM < (1L shl 31), "reader limit above 2 GiB cannot be a 32-bit size_t")
    }

    // ---- reproducible by another implementation, and by a device with another ladder ---------

    /** Argon2id with the same inputs from PyNaCl (libsodium of the server's test client). */
    @ParameterizedTest
    @ValueSource(ints = [0, 1, 2])
    fun `every rung reproduces the PyNaCl value`(index: Int) {
        val (ops, mem) = ladder[index]
        val params = KdfParams(ops, mem, ByteArray(KdfParams.SALT_BYTES) { it.toByte() })
        val key = PasswordKdf.derive(PASSWORD, params)
        assertEquals(PYNACL_KEYS[index], key.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `a device with another ladder opens what a low-memory device wrote, and the other way round`() {
        val vk = Sodium.random(32)
        val rk = RecoveryKey.generate()
        val kekRk = VaultKeyWraps.recoveryKek(rk)

        // Device A has little free memory: the ladder offers only the last rung.
        val ladderA = PasswordKdf.ladderFor(100 * mib)
        val (paramsA, kekA) = PasswordKdf.deriveNew(PASSWORD, ladderA)
        assertEquals(weakest.second, paramsA.memLimit)
        val bundleA = VaultKeyWraps.bundle(vk, 1, kekRk, kekA, paramsA)

        // Device B has plenty: its own ladder starts at 1 GiB, but a reader uses the stored parameters.
        val ladderB = PasswordKdf.ladderFor(8 * gib)
        assertEquals(strongest, ladderB.first())
        assertNotEquals(ladderA.first(), ladderB.first())
        val openedOnB = VaultKeyWraps.openWithPassword(PASSWORD, bundleA.passwordWrap!!, bundleA.passwordKdf!!, 1)
        assertArrayEquals(vk, openedOnB.vaultKey)

        // And the strongest rung, written by B, is read by A.
        val (paramsB, kekB) = PasswordKdf.deriveNew(PASSWORD, listOf(strongest))
        assertEquals(strongest.second, paramsB.memLimit)
        val bundleB = VaultKeyWraps.bundle(vk, 1, kekRk, kekB, paramsB)
        val openedOnA = VaultKeyWraps.openWithPassword(PASSWORD, bundleB.passwordWrap!!, bundleB.passwordKdf!!, 1)
        assertArrayEquals(vk, openedOnA.vaultKey)
    }

    private companion object {
        const val PASSWORD = "correct horse battery staple pässwörd"
        const val SEED = 20_261_013L

        /** `nacl.pwhash.argon2id.kdf(32, NFC(password), bytes(range(16)), ops, mem)` for each rung. */
        val PYNACL_KEYS =
            listOf(
                "51538bb63f2d6ea7cd883f4bbd4ddd98d62e7b76e93471b46030b42e85d0cbd3",
                "581b45cbd76ad83591071d601ea35a73b61cd125d1e030fd69bcdffcdb7fda5b",
                "85db3d0c152c55adc3df7280684edbcc1bb88c20dbe2ae269243d863d6a7b338",
            )
    }
}
