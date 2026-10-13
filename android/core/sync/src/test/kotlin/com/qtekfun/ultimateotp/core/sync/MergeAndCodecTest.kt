// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.model.ItemCodec
import com.qtekfun.ultimateotp.core.sync.model.Merge
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

class MergeAndCodecTest {
    private val id = UUID.fromString("7d444840-9dc0-11d1-b245-5ffdce74fad2")

    private fun item(
        label: String = "alice",
        updated: Long = 1,
        by: String = "dev_a",
        counter: Long? = null,
    ): VaultItem {
        val uri =
            if (counter == null) {
                "otpauth://totp/Ex:$label?secret=JBSWY3DPEHPK3PXP"
            } else {
                "otpauth://hotp/Ex:$label?secret=JBSWY3DPEHPK3PXP&counter=$counter"
            }
        return VaultItem(id, OtpAuthUri.parse(uri), created = 1, updated = updated, updatedBy = by)
    }

    @Test
    fun `codec round-trips and keeps unknown fields`() {
        val withExtra = item().copy(extra = mapOf("future" to JsonPrimitive("x")))
        val bytes = ItemCodec.encode(withExtra)
        assertEquals("x", Json.parseToJsonElement(String(bytes)).jsonObject["future"]?.let { (it as JsonPrimitive).content })
        assertEquals(withExtra, ItemCodec.decode(id, bytes))
    }

    @Test
    fun `delete versus edit keeps the edit, on both sides`() {
        val edited = item()
        assertEquals(Merge.Result(edited, dirty = true), Merge.resolve(edited, null))
        assertEquals(Merge.Result(edited, dirty = false), Merge.resolve(null, edited))
        assertNull(Merge.resolve(null, null).item)
    }

    @Test
    fun `newer edit wins and the other is kept as a conflict copy`() {
        val local = item(label = "local", updated = 5)
        val remote = item(label = "remote", updated = 3)
        val r = Merge.resolve(local, remote, newId = { UUID(0, 1) })
        assertEquals("local", r.item!!.otp.label)
        assertTrue(r.dirty)
        val copy = assertNotNull(r.conflictCopy).let { r.conflictCopy!! }
        assertEquals("remote", copy.otp.label)
        assertTrue(Merge.CONFLICT_TAG in copy.otp.tags)

        val older = Merge.resolve(item(label = "local", updated = 1), remote, newId = { UUID(0, 2) })
        assertEquals("remote", older.item!!.otp.label)
        assertFalse(older.dirty)
    }

    @Test
    fun `HOTP counters take the maximum without a conflict copy`() {
        val r = Merge.resolve(item(counter = 9, updated = 1), item(counter = 4, updated = 2))
        assertEquals(9L, r.item!!.otp.counter)
        assertTrue(r.dirty)
        assertNull(r.conflictCopy)
    }
}
