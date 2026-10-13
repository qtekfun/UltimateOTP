// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

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
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

/** The vault blob (crypto-format.md §6.2) for arbitrary plaintexts, bindings and corruption. */
@OptIn(ExperimentalKotest::class)
class ItemCipherPropertiesTest {
    private val config = PropTestConfig(iterations = 150, seed = 20_261_013L)
    private val key = ItemCipher.itemKey(ByteArray(32) { it.toByte() })
    private val plaintexts = Arb.byteArray(Arb.int(0..3_000), Arb.byte())
    private val shortPlaintexts = Arb.byteArray(Arb.int(0..64), Arb.byte())

    private fun binding(
        n: Long,
        account: String = "acc_$n",
        version: Long = n and 0xFFFF,
        epoch: Long = (n and 0xFF) + 1,
    ) = ItemBinding(account, UUID(n, n.inv()), version, epoch)

    @Test
    fun `any plaintext round-trips and the blob size reveals only its 256-byte bucket`(): Unit =
        runBlocking {
            checkAll(config, plaintexts, Arb.long(0L..Long.MAX_VALUE)) { plain, n ->
                val b = binding(n)
                val blob = ItemCipher.encrypt(key, b, plain)
                assertArrayEquals(plain, ItemCipher.decrypt(key, b, blob))
                assertEquals(ItemCipher.keyEpochOf(blob), b.keyEpoch)
                val overhead = 1 + 4 + Aead.NONCE_BYTES + Aead.TAG_BYTES
                assertEquals(0, (blob.size - overhead) % ItemCipher.PAD_BLOCK)
                assertEquals((plain.size / ItemCipher.PAD_BLOCK + 1) * ItemCipher.PAD_BLOCK, blob.size - overhead)
            }
        }

    @Test
    fun `a blob opens only for the item, version, account and epoch it was written for`(): Unit =
        runBlocking {
            checkAll(config, shortPlaintexts, Arb.long(1L..1_000_000L)) { plain, n ->
                val b = binding(n)
                val blob = ItemCipher.encrypt(key, b, plain)
                val others =
                    listOf(
                        b.copy(itemId = UUID(n + 1, n.inv())),
                        b.copy(itemVersion = b.itemVersion + 1),
                        b.copy(accountId = b.accountId + "x"),
                        b.copy(keyEpoch = b.keyEpoch + 1),
                    )
                others.forEach { other -> assertThrows<CryptoException> { ItemCipher.decrypt(key, other, blob) } }
            }
        }

    @Test
    fun `flipping any single bit of a blob is detected`(): Unit =
        runBlocking {
            checkAll(config, Arb.long(1L..1_000_000L), Arb.int(0..Int.MAX_VALUE), Arb.int(0..7)) { n, position, bit ->
                val b = binding(n)
                val blob = ItemCipher.encrypt(key, b, "otp item $n".toByteArray())
                val bad = blob.copyOf()
                bad[position % bad.size] = (bad[position % bad.size].toInt() xor (1 shl bit)).toByte()
                assertThrows<CryptoException> { ItemCipher.decrypt(key, b, bad) }
                assertArrayEquals("otp item $n".toByteArray(), ItemCipher.decrypt(key, b, blob)) // the original is intact
            }
        }

    @Test
    fun `an item above the size cap is refused, not truncated`() {
        val huge = ByteArray(ItemCipher.MAX_PADDED)
        assertThrows<CryptoException.InvalidFormat> { ItemCipher.encrypt(key, binding(1), huge) }
    }
}
