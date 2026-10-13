// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.model.ItemCodec
import com.qtekfun.ultimateotp.core.sync.model.ItemOrder
import com.qtekfun.ultimateotp.core.sync.model.Merge
import com.qtekfun.ultimateotp.core.sync.model.OrderKeys
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID
import kotlin.random.Random

class TrashOrderMergeTest {
    private fun id(n: Int) = UUID(0, n.toLong())

    private fun item(
        n: Int,
        issuer: String = "Issuer$n",
        label: String = "acct",
        updated: Long = 1,
        by: String = "dev_a",
    ) = VaultItem(
        id(n),
        OtpAuthUri.parse("otpauth://totp/$issuer:$label?secret=JBSWY3DPEHPK3PXP&issuer=$issuer"),
        created = 1,
        updated = updated,
        updatedBy = by,
    )

    // ---- codec ------------------------------------------------------------------------------

    @Test
    fun `new fields round-trip and stay absent when unused`() {
        val plain = item(1)
        val json = String(ItemCodec.encode(plain))
        assertFalse("trashed" in json || "order" in json || "autofill" in json)

        val rich =
            plain.copy(
                trashed = true,
                trashChanged = 99,
                order = "V1",
                orderChanged = 7,
                autofill = listOf("com.example.app", "example.com"),
            )
        assertEquals(rich, ItemCodec.decode(rich.id, ItemCodec.encode(rich)))
    }

    @Test
    fun `an older client's JSON without the new fields decodes to defaults`() {
        val decoded = ItemCodec.decode(id(1), ItemCodec.encode(item(1)))
        assertFalse(decoded.trashed)
        assertNull(decoded.order)
        assertTrue(decoded.autofill.isEmpty())
    }

    // ---- trash merge ------------------------------------------------------------------------

    @Test
    fun `trash on one device and an edit on another keep both`() {
        val base = item(1, updated = 1)
        val trashedLocal = base.copy(trashed = true, trashChanged = 10)
        val editedRemote = base.copy(notes = "edited", updated = 5, updatedBy = "dev_b")
        val r = Merge.resolve(trashedLocal, editedRemote, base = base)
        val merged = r.item!!
        assertTrue(merged.trashed)
        assertEquals("edited", merged.notes)
        assertTrue(r.dirty)
        assertNull(r.conflictCopy)
    }

    @Test
    fun `restore after trash wins when it is newer, on both sides`() {
        val trashed = item(1).copy(trashed = true, trashChanged = 10)
        val restored = item(1).copy(trashed = false, trashChanged = 20)
        assertFalse(Merge.resolve(trashed, restored).item!!.trashed)
        assertFalse(Merge.resolve(restored, trashed).item!!.trashed)
        assertTrue(Merge.resolve(restored.copy(trashChanged = 5), trashed).item!!.trashed)
    }

    @Test
    fun `merge is symmetric for trash and order, whoever pulls`() {
        val rnd = Random(7)
        repeat(200) {
            fun side(by: String) =
                item(1, updated = rnd.nextLong(1, 4), by = by).copy(
                    trashed = rnd.nextBoolean(),
                    trashChanged = rnd.nextLong(0, 4),
                    order = listOf(null, "V", "k", "3").random(rnd),
                    orderChanged = rnd.nextLong(0, 4),
                    notes = listOf("", "n").random(rnd),
                )

            val a = side("dev_a")
            val b = side("dev_b")
            val ab = Merge.resolve(a, b, newId = { UUID(0, 99) }).item!!
            val ba = Merge.resolve(b, a, newId = { UUID(0, 99) }).item!!
            assertEquals(ab, ba)
        }
    }

    @Test
    fun `an expired trashed item is detected by the retention window`() {
        val t = item(1).copy(trashed = true, trashChanged = 1_000)
        assertFalse(t.trashExpired(1_000 + VaultItem.TRASH_RETENTION_MS - 1))
        assertTrue(t.trashExpired(1_000 + VaultItem.TRASH_RETENTION_MS))
        assertFalse(item(1).trashExpired(Long.MAX_VALUE))
    }

    // ---- order keys -------------------------------------------------------------------------

    @Test
    fun `between always yields a strictly ordered valid key`() {
        val rnd = Random(42)
        val keys = mutableListOf<String>()
        repeat(2000) {
            val i = if (keys.isEmpty()) 0 else rnd.nextInt(keys.size + 1)
            val lo = keys.getOrNull(i - 1)
            val hi = keys.getOrNull(i)
            val k = OrderKeys.between(lo, hi)
            assertTrue(OrderKeys.isValid(k), k)
            if (lo != null) assertTrue(lo < k, "$lo < $k")
            if (hi != null) assertTrue(k < hi, "$k < $hi")
            keys.add(i, k)
        }
        assertEquals(keys.sorted(), keys)
        assertEquals(keys.size, keys.toSet().size)
    }

    @Test
    fun `between rejects unordered or invalid bounds`() {
        assertThrows<IllegalArgumentException> { OrderKeys.between("b", "a") }
        assertThrows<IllegalArgumentException> { OrderKeys.between("a", "a") }
        assertThrows<IllegalArgumentException> { OrderKeys.between("a0", null) }
        assertThrows<IllegalArgumentException> { OrderKeys.between(null, "x y") }
    }

    @Test
    fun `initial keys are ascending, valid and the same on every call`() {
        for (n in listOf(0, 1, 2, 5, 100, 5000)) {
            val keys = OrderKeys.initial(n)
            assertEquals(n, keys.size)
            assertEquals(keys.sorted(), keys)
            assertEquals(n, keys.toSet().size)
            assertTrue(keys.all(OrderKeys::isValid))
            assertEquals(keys, OrderKeys.initial(n))
        }
    }

    // ---- move -------------------------------------------------------------------------------

    private fun apply(
        list: List<VaultItem>,
        changes: List<VaultItem>,
    ): List<VaultItem> {
        val by = changes.associateBy { it.id }
        return ItemOrder.sorted(list.map { by[it.id] ?: it })
    }

    @Test
    fun `first move keys the whole list, later moves change one entry`() {
        val list = ItemOrder.sorted((1..5).map { item(it, issuer = "Z${6 - it}") })
        assertTrue(list.all { it.order == null })
        val c1 = ItemOrder.move(list, 0, 3, now = 100)
        assertEquals(5, c1.size)
        val after1 = apply(list, c1)
        assertEquals(list.map { it.id }.let { ids -> ids.toMutableList().also { l -> l.add(3, l.removeAt(0)) } }, after1.map { it.id })

        val c2 = ItemOrder.move(after1, 4, 1, now = 200)
        assertEquals(1, c2.size)
        assertEquals(200L, c2[0].orderChanged)
        val after2 = apply(after1, c2)
        assertEquals(after1.map { it.id }.toMutableList().also { l -> l.add(1, l.removeAt(4)) }, after2.map { it.id })
    }

    @Test
    fun `move to the same index changes nothing and bad indexes are refused`() {
        val list = ItemOrder.sorted((1..3).map { item(it) })
        assertTrue(ItemOrder.move(list, 1, 1, 1).isEmpty())
        assertThrows<IllegalArgumentException> { ItemOrder.move(list, 0, 3, 1) }
        assertThrows<IllegalArgumentException> { ItemOrder.move(list, -1, 0, 1) }
    }

    @Test
    fun `random moves always land the entry at the requested index`() {
        val rnd = Random(2026)
        var list = ItemOrder.sorted((1..12).map { item(it, issuer = "I${rnd.nextInt(5)}") })
        var now = 1L
        repeat(500) {
            val from = rnd.nextInt(list.size)
            val to = rnd.nextInt(list.size)
            val expected = list.map { it.id }.toMutableList().also { l -> l.add(to, l.removeAt(from)) }
            val changes = ItemOrder.move(list, from, to, now++)
            list = apply(list, changes)
            assertEquals(expected, list.map { it.id })
        }
    }

    @Test
    fun `moving among entries added after a manual order keeps them after the placed ones`() {
        val placed = apply(ItemOrder.sorted((1..3).map { item(it) }), ItemOrder.move(ItemOrder.sorted((1..3).map { item(it) }), 0, 2, 1))
        val withNew = ItemOrder.sorted(placed + item(9, issuer = "AAA"))
        assertEquals(id(9), withNew.last().id)
        // Dragging a placed entry to the end passes the unplaced one only if asked to.
        val changes = ItemOrder.move(withNew, 0, 2, 5)
        assertEquals(1, changes.size)
        assertEquals(withNew[1].id, apply(withNew, changes)[0].id)
    }

    // ---- concurrent reorders ----------------------------------------------------------------

    @Test
    fun `two devices moving different entries merge to the same list on both`() {
        val base = apply(ItemOrder.sorted((1..6).map { item(it) }), ItemOrder.move(ItemOrder.sorted((1..6).map { item(it) }), 0, 5, 1))
        val devA = apply(base, ItemOrder.move(base, 0, 2, now = 100)) // device A moves entry at 0
        val devB = apply(base, ItemOrder.move(base, 5, 1, now = 120)) // device B moves the last one
        val aById = devA.associateBy { it.id }
        val bById = devB.associateBy { it.id }

        // Each item is merged on its own, as the sync engine does it, from both points of view.
        fun mergedOn(
            mine: Map<UUID, VaultItem>,
            theirs: Map<UUID, VaultItem>,
        ) = ItemOrder.sorted(mine.keys.map { Merge.resolve(mine.getValue(it), theirs.getValue(it)).item!! })

        val onA = mergedOn(aById, bById)
        val onB = mergedOn(bById, aById)
        assertEquals(onA.map { it.id }, onB.map { it.id })
        // Both moves are visible in the result.
        assertNotNull(onA.firstOrNull { it.id == base[0].id }?.order)
        assertTrue(onA.map { it.id } != base.map { it.id })
    }

    @Test
    fun `two devices moving the same entry keep the later move on both`() {
        val base = apply(ItemOrder.sorted((1..4).map { item(it) }), ItemOrder.move(ItemOrder.sorted((1..4).map { item(it) }), 0, 3, 1))
        val moved = base[0].id
        val devA = apply(base, ItemOrder.move(base, 0, 2, now = 100))
        val devB = apply(base, ItemOrder.move(base, 0, 3, now = 200))
        val aItem = devA.first { it.id == moved }
        val bItem = devB.first { it.id == moved }
        val m1 = Merge.resolve(aItem, bItem).item!!
        val m2 = Merge.resolve(bItem, aItem).item!!
        assertEquals(m1.order, m2.order)
        assertEquals(bItem.order, m1.order)
    }

    @Test
    fun `two devices placing the same list for the first time agree on every key`() {
        val list = ItemOrder.sorted((1..8).map { item(it) })
        val a = apply(list, ItemOrder.move(list, 0, 4, now = 10))
        val b = apply(list, ItemOrder.move(list, 0, 4, now = 20))
        assertEquals(a.map { it.order }, b.map { it.order })
    }

    @Test
    fun `equal keys on different entries are ordered by id on every device`() {
        val x = item(2).copy(order = "V", orderChanged = 1)
        val y = item(1).copy(order = "V", orderChanged = 1)
        assertEquals(listOf(id(1), id(2)), ItemOrder.sorted(listOf(x, y)).map { it.id })
        assertEquals(listOf(id(1), id(2)), ItemOrder.sorted(listOf(y, x)).map { it.id })
        // A move next to a tie re-keys instead of failing.
        val changes = ItemOrder.move(ItemOrder.sorted(listOf(x, y, item(3).copy(order = "k", orderChanged = 1))), 2, 0, 5)
        assertTrue(changes.isNotEmpty())
    }
}
