// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.UUID

class SortModeTest {
    private fun item(
        n: Int,
        issuer: String,
        label: String,
        favorite: Boolean = false,
    ) = VaultItem(
        id = UUID(0L, n.toLong()),
        otp =
            OtpParams(
                type = OtpType.TOTP,
                secret = ByteArray(10) { 1 },
                algorithm = OtpAlgorithm.SHA1,
                digits = 6,
                period = 30,
                issuer = issuer,
                label = label,
            ),
        favorite = favorite,
        created = n.toLong(),
        updated = n.toLong(),
        updatedBy = VaultItem.LOCAL_DEVICE,
    )

    private val items =
        listOf(
            item(1, "Zeta", "z@x.org"),
            item(2, "", "bob@x.org"),
            item(3, "alpha", "a@x.org", favorite = true),
            item(4, "", "Carol@x.org"),
        )

    private fun labels(
        list: List<VaultItem>,
        mode: SortMode,
    ) = ItemOrder.sorted(list, mode).map { it.otp.label }

    @Test
    fun `alphabetical puts pinned first and uses the account when the provider is empty`() {
        assertEquals(listOf("a@x.org", "bob@x.org", "Carol@x.org", "z@x.org"), labels(items, SortMode.ALPHABETICAL))
    }

    @Test
    fun `newest and oldest follow the creation time, pinned first`() {
        assertEquals(listOf("a@x.org", "Carol@x.org", "bob@x.org", "z@x.org"), labels(items, SortMode.NEWEST))
        assertEquals(listOf("a@x.org", "z@x.org", "bob@x.org", "Carol@x.org"), labels(items, SortMode.OLDEST))
    }

    @Test
    fun `manual keeps dragged entries first and the other modes ignore the keys`() {
        val dragged = items.map { if (it.otp.label == "z@x.org") it.copy(order = "a") else it }
        assertEquals("z@x.org", labels(dragged, SortMode.MANUAL).first())
        assertEquals("a@x.org", labels(dragged, SortMode.ALPHABETICAL).first())
    }
}
