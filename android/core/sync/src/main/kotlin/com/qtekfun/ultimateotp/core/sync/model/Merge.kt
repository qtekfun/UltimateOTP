// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import com.qtekfun.ultimateotp.core.otp.OtpType
import java.util.UUID

/**
 * Per-item merge of a local unsynced change with the server's version (design.md §4.4).
 * Never loses a secret: delete vs edit keeps the edit, two edits keep the newer one and a copy of
 * the other, HOTP counters take the maximum so no code is ever reused.
 */
object Merge {
    const val CONFLICT_TAG = "conflict"

    /** What to store after merging one item. */
    data class Result(
        /** The item that stays under the original id; null if it stays deleted. */
        val item: VaultItem?,
        /** True if [item] differs from the server's and must still be committed. */
        val dirty: Boolean,
        /** A new local item holding the losing side of an edit/edit conflict. */
        val conflictCopy: VaultItem? = null,
    )

    /**
     * [local] null = deleted locally; [remote] null = deleted on the server. [base] is the version
     * the local change started from (the last committed one), when known: a side whose content
     * still equals it only changed trash state or position, so it never produces a conflict copy.
     */
    fun resolve(
        local: VaultItem?,
        remote: VaultItem?,
        base: VaultItem? = null,
        newId: () -> UUID = UUID::randomUUID,
    ): Result =
        when {
            local == null && remote == null -> Result(null, dirty = false)

            // Edit wins over delete, on either side.
            local == null -> Result(remote, dirty = false)

            remote == null -> Result(local, dirty = true)

            else -> mergeEdits(local, remote, base, newId)
        }

    private fun mergeEdits(
        local: VaultItem,
        remote: VaultItem,
        base: VaultItem?,
        newId: () -> UUID,
    ): Result {
        val localEdited = base == null || !local.sameContent(base)
        val remoteEdited = base == null || !remote.sameContent(base)
        val localWins = localKeepsContent(local, remote, localEdited, remoteEdited)
        val winner = if (localWins) local else remote
        val loser = if (localWins) remote else local
        val merged = withState(withHotpCounter(winner, loser), local, remote)
        // A side that still has the base content only moved or trashed the item: nothing to keep.
        val concurrent = localEdited && remoteEdited && !winner.sameContent(loser) && !sameButCounter(winner, loser)
        val copy =
            if (concurrent) {
                loser.copy(
                    id = newId(),
                    otp = loser.otp.copy(tags = (loser.otp.tags + CONFLICT_TAG).distinct()),
                    trashed = merged.trashed,
                    trashChanged = merged.trashChanged,
                    order = null,
                    orderChanged = 0,
                )
            } else {
                null
            }
        val dirty = !merged.sameContent(remote) || merged.updated != remote.updated || !merged.sameState(remote)
        return Result(merged, dirty = dirty, conflictCopy = copy)
    }

    /** The newer edit wins; a side that did not edit the content never beats one that did. */
    private fun localKeepsContent(
        local: VaultItem,
        remote: VaultItem,
        localEdited: Boolean,
        remoteEdited: Boolean,
    ): Boolean =
        when {
            localEdited && !remoteEdited -> true
            !localEdited && remoteEdited -> false
            else -> compareValuesBy(local, remote, { it.updated }, { it.updatedBy }) > 0
        }

    /** Trash state and position come from whichever side changed them last, apart from the content. */
    private fun withState(
        item: VaultItem,
        a: VaultItem,
        b: VaultItem,
    ): VaultItem {
        val trashSide = newer(a, b, { it.trashChanged }, { if (it.trashed) 1 else 0 })
        val orderSide = newer(a, b, { it.orderChanged }, { 0 }, { it.order.orEmpty() })
        return item.copy(
            trashed = trashSide.trashed,
            trashChanged = trashSide.trashChanged,
            order = orderSide.order,
            orderChanged = orderSide.orderChanged,
        )
    }

    /** HOTP counters take the maximum so no code is ever reused. */
    private fun withHotpCounter(
        winner: VaultItem,
        loser: VaultItem,
    ): VaultItem =
        if (winner.otp.type == OtpType.HOTP && loser.otp.type == OtpType.HOTP && loser.otp.counter > winner.otp.counter) {
            winner.copy(otp = winner.otp.copy(counter = loser.otp.counter))
        } else {
            winner
        }

    /**
     * Trash state and manual position merge on their own, so a reorder on one device and an edit on
     * another both survive: the side with the newest change time wins, ties go to the larger
     * tie-break values, so every device picks the same side.
     */
    private fun newer(
        a: VaultItem,
        b: VaultItem,
        time: (VaultItem) -> Long,
        flag: (VaultItem) -> Int,
        text: (VaultItem) -> String = { "" },
    ): VaultItem = if (compareValuesBy(a, b, time, flag, text) >= 0) a else b

    private fun sameButCounter(
        a: VaultItem,
        b: VaultItem,
    ): Boolean = a.otp.type == OtpType.HOTP && a.copy(otp = a.otp.copy(counter = 0)).sameContent(b.copy(otp = b.otp.copy(counter = 0)))
}
