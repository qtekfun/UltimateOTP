// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.model.ItemCodec
import com.qtekfun.ultimateotp.core.sync.model.Merge
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import io.kotest.common.ExperimentalKotest
import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.enum
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * The guarantees design.md §4.4 makes about the per-item merge ("never loses a secret", HOTP
 * counters "take the maximum so no code is ever reused") and about the item codec (unknown fields
 * of newer clients survive a rewrite), checked for random items rather than a handful of examples.
 */
@OptIn(ExperimentalKotest::class)
class MergeAndCodecPropertiesTest {
    private val config = PropTestConfig(iterations = 400, seed = 20_261_013L)
    private val id = UUID.fromString("7d444840-9dc0-11d1-b245-5ffdce74fad2")

    private val text = Arb.string(0..12).map { s -> s.filter { !it.isSurrogate() } }
    private val device = Arb.int(1..3).map { "dev_$it" }

    private fun items(
        type: OtpType? = null,
        updated: Arb<Long> = Arb.long(1L..1_000L),
    ): Arb<VaultItem> =
        arbitrary {
            val t = type ?: Arb.enum<OtpType>().bind()
            val steam = t == OtpType.STEAM
            val otp =
                OtpParams(
                    type = t,
                    secret = Arb.byteArray(Arb.int(1..40), Arb.byte()).bind(),
                    algorithm = if (steam) OtpAlgorithm.SHA1 else Arb.enum<OtpAlgorithm>().bind(),
                    digits = if (steam) OtpParams.STEAM_DIGITS else Arb.int(5..10).bind(),
                    // The codec writes `counter` for HOTP and `period` for the others only.
                    period = if (t == OtpType.HOTP) OtpParams.DEFAULT_PERIOD else Arb.int(1..3600).bind(),
                    counter = if (t == OtpType.HOTP) Arb.long(0L..1_000_000L).bind() else 0,
                    issuer = text.bind(),
                    label = text.bind(),
                    tags = Arb.int(0..3).bind().let { n -> List(n) { "tag$it" } },
                )
            VaultItem(
                id = id,
                otp = otp,
                notes = text.bind(),
                favorite = Arb.boolean().bind(),
                icon = if (Arb.boolean().bind()) text.bind() else null,
                created = Arb.long(0L..1_000L).bind(),
                updated = updated.bind(),
                updatedBy = device.bind(),
                extra = if (Arb.boolean().bind()) mapOf("future" to JsonPrimitive(text.bind())) else emptyMap(),
            )
        }

    // ---- codec --------------------------------------------------------------------------------

    @Test
    fun `the item plaintext decodes to what was encoded, extra fields included`(): Unit =
        runBlocking {
            checkAll(config, items()) { item ->
                assertEquals(item, ItemCodec.decode(id, ItemCodec.encode(item)))
            }
        }

    @Test
    fun `encoding is deterministic and re-encoding a decoded item changes nothing`(): Unit =
        runBlocking {
            checkAll(config, items()) { item ->
                val bytes = ItemCodec.encode(item)
                assertTrue(bytes.contentEquals(ItemCodec.encode(item)))
                assertTrue(bytes.contentEquals(ItemCodec.encode(ItemCodec.decode(id, bytes))))
            }
        }

    // ---- merge --------------------------------------------------------------------------------

    private fun content(item: VaultItem?): List<Any?> =
        item?.let { listOf(it.otp, it.notes, it.favorite, it.icon, it.extra, it.updated) }.orEmpty()

    @Test
    fun `merging is symmetric when the two writes can be told apart`(): Unit =
        runBlocking {
            // Distinct (updated, updatedBy): which side is "local" must not change the outcome.
            checkAll(config, items(), items()) { a, b ->
                if (a.updated == b.updated && a.updatedBy == b.updatedBy) return@checkAll
                val ab = Merge.resolve(a, b) { UUID(0, 1) }
                val ba = Merge.resolve(b, a) { UUID(0, 1) }
                assertEquals(content(ab.item), content(ba.item))
                assertEquals(ab.conflictCopy?.otp, ba.conflictCopy?.otp)
            }
        }

    @Test
    fun `merging twice changes nothing and an item merged with itself needs no commit`(): Unit =
        runBlocking {
            checkAll(config, items(), items()) { a, b ->
                val first = Merge.resolve(a, b) { UUID(0, 1) }
                val again = Merge.resolve(first.item, b) { UUID(0, 2) }
                assertEquals(first.item, again.item)
                val self = Merge.resolve(a, a)
                assertEquals(a, self.item)
                assertTrue(!self.dirty)
                assertNull(self.conflictCopy)
            }
        }

    @Test
    fun `nothing is lost and no HOTP counter goes backwards`(): Unit =
        runBlocking {
            checkAll(config, items(OtpType.HOTP), items(OtpType.HOTP)) { a, b ->
                val r = Merge.resolve(a, b) { UUID(0, 1) }
                val merged = requireNotNull(r.item)
                assertTrue(merged.otp.counter >= maxOf(a.otp.counter, b.otp.counter))
            }
            checkAll(config, items(), items()) { a, b ->
                val r = Merge.resolve(a, b) { UUID(0, 1) }
                val merged = requireNotNull(r.item)
                // Either both writes have the same content, or the losing one is kept as a copy.
                val sameContent = a.sameContent(b) || (a.otp.type == OtpType.HOTP && r.conflictCopy == null)
                assertTrue(sameContent || r.conflictCopy != null, "a differing edit was dropped: $a vs $b")
                val copy = r.conflictCopy
                if (copy != null) {
                    assertTrue(Merge.CONFLICT_TAG in copy.otp.tags)
                    assertTrue(copy.id != merged.id)
                    assertTrue(copy.otp.secret.contentEquals(a.otp.secret) || copy.otp.secret.contentEquals(b.otp.secret))
                }
            }
        }

    @Test
    fun `an edit always beats a delete, on either side`(): Unit =
        runBlocking {
            checkAll(config, items()) { item ->
                assertEquals(item, Merge.resolve(item, null).item)
                assertEquals(item, Merge.resolve(null, item).item)
                assertNull(Merge.resolve(null, null).item)
            }
        }
}
