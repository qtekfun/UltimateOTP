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

    /** [local] null = deleted locally; [remote] null = deleted on the server. */
    fun resolve(
        local: VaultItem?,
        remote: VaultItem?,
        newId: () -> UUID = UUID::randomUUID,
    ): Result =
        when {
            local == null && remote == null -> Result(null, dirty = false)

            // Edit wins over delete, on either side.
            local == null -> Result(remote, dirty = false)

            remote == null -> Result(local, dirty = true)

            else -> mergeEdits(local, remote, newId)
        }

    private fun mergeEdits(
        local: VaultItem,
        remote: VaultItem,
        newId: () -> UUID,
    ): Result {
        val localWins = compareValuesBy(local, remote, { it.updated }, { it.updatedBy }) > 0
        val winner = if (localWins) local else remote
        val loser = if (localWins) remote else local
        val merged =
            if (winner.otp.type == OtpType.HOTP && loser.otp.type == OtpType.HOTP && loser.otp.counter > winner.otp.counter) {
                winner.copy(otp = winner.otp.copy(counter = loser.otp.counter))
            } else {
                winner
            }
        val copy =
            if (winner.sameContent(loser) || sameButCounter(winner, loser)) {
                null
            } else {
                loser.copy(
                    id = newId(),
                    otp = loser.otp.copy(tags = (loser.otp.tags + CONFLICT_TAG).distinct()),
                )
            }
        return Result(merged, dirty = !merged.sameContent(remote) || merged.updated != remote.updated, conflictCopy = copy)
    }

    private fun sameButCounter(
        a: VaultItem,
        b: VaultItem,
    ): Boolean = a.otp.type == OtpType.HOTP && a.copy(otp = a.otp.copy(counter = 0)).sameContent(b.copy(otp = b.otp.copy(counter = 0)))
}
