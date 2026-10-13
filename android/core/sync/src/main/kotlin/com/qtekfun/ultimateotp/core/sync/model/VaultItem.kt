// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import com.qtekfun.ultimateotp.core.otp.OtpParams
import kotlinx.serialization.json.JsonElement
import java.util.UUID

/**
 * One decrypted vault entry (crypto-format.md §6.1). [extra] keeps fields written by newer
 * clients so a rewrite does not drop them. Holds a secret: never log it.
 */
data class VaultItem(
    val id: UUID,
    val otp: OtpParams,
    val notes: String = "",
    val favorite: Boolean = false,
    val icon: String? = null,
    val created: Long,
    val updated: Long,
    val updatedBy: String,
    val extra: Map<String, JsonElement> = emptyMap(),
    /** In the trash (deleted but restorable until [TRASH_RETENTION_MS] after [trashChanged]). */
    val trashed: Boolean = false,
    /** When [trashed] last changed (ms): the merge keeps the newest state. */
    val trashChanged: Long = 0,
    /** Manual position: a fractional key (see [OrderKeys]); null = never placed by hand. */
    val order: String? = null,
    /** When [order] last changed (ms): the merge keeps the newest position. */
    val orderChanged: Long = 0,
    /** Apps and web domains this entry's code may be offered for (autofill, docs/autofill.md). */
    val autofill: List<String> = emptyList(),
) {
    /** No secret, issuer or label: safe for logs. */
    override fun toString(): String = "VaultItem(id=$id, type=${otp.type}, updated=$updated)"

    /** Same account content, ignoring who/when it was written. */
    fun sameContent(other: VaultItem): Boolean =
        otp == other.otp && notes == other.notes && favorite == other.favorite && icon == other.icon && extra == other.extra &&
            autofill == other.autofill

    /** Same trash state and position: the two parts of an item that merge on their own. */
    fun sameState(other: VaultItem): Boolean =
        trashed == other.trashed && trashChanged == other.trashChanged && order == other.order && orderChanged == other.orderChanged

    /** True once the item has been in the trash longer than [TRASH_RETENTION_MS] at [now]. */
    fun trashExpired(now: Long): Boolean = trashed && now - trashChanged >= TRASH_RETENTION_MS

    companion object {
        /** `updated_by` of items written while the vault had no account. */
        const val LOCAL_DEVICE = "local"

        /** 30 days: how long a trashed item stays restorable. */
        const val TRASH_RETENTION_MS = 30L * 24 * 60 * 60 * 1000
    }
}
