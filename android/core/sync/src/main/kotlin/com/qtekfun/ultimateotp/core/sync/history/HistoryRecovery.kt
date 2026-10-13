// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.history

import com.qtekfun.ultimateotp.core.crypto.B64u
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.SyncStore
import com.qtekfun.ultimateotp.core.sync.api.HistoryVersion
import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import java.util.UUID

/** An entry the server still holds although it was removed (permanently deleted less than the retention ago). */
class RecoverableEntry(
    val item: VaultItem,
    /** When it was deleted, Unix seconds. */
    val deletedAt: Long,
)

/**
 * The server's version history (contract 1.2.0) as the app's safety net behind the local trash:
 * entries removed for good within the retention window, and older versions of an entry.
 *
 * Blobs are decrypted with the item version they came with (part of their authenticated data) and
 * written back as an ordinary pending change, committed by the next sync. Nothing here trusts the
 * server for content: a blob that does not authenticate under the vault key is skipped.
 */
class HistoryRecovery(
    private val store: SyncStore,
    private val engine: SyncEngine,
    private val apiFor: (String) -> UotpApi,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private suspend fun account(): AccountState = store.account() ?: error("no account")

    private fun api(account: AccountState): UotpApi = apiFor(account.serverUrl).also { it.clockOffset = account.clockOffset }

    private fun signer(account: AccountState) = Signer(store.deviceKeys(), account.deviceId)

    /** Entries deleted within the retention, newest first. Ones that cannot be read (old key epoch) are left out. */
    suspend fun deletedEntries(): List<RecoverableEntry> {
        val account = account()
        val cipher = store.cipher()
        return api(account)
            .vaultTrash(signer(account))
            .items
            .filter { it.keyEpoch == account.keyEpoch }
            .sortedByDescending { it.deletedAt }
            .mapNotNull { t ->
                val id = UUID.fromString(t.itemId)
                runCatching {
                    cipher.open(
                        id,
                        com.qtekfun.ultimateotp.core.crypto.B64u
                            .decode(t.blob),
                        t.version,
                    )
                }.getOrNull()
                    ?.let { RecoverableEntry(it, t.deletedAt) }
            }
    }

    /** Puts a removed entry back (a pending change under its old id) and syncs. @return false if it is not recoverable. */
    suspend fun restoreDeleted(itemId: UUID): Boolean {
        val entry = deletedEntries().firstOrNull { it.item.id == itemId } ?: return false
        val account = account()
        val restored =
            entry.item.copy(
                trashed = false,
                trashChanged = clock(),
                updated = clock(),
                updatedBy = account.deviceId,
            )
        writePending(restored)
        engine.sync()
        return true
    }

    /** The committed versions the server still holds, newest first. */
    suspend fun versions(
        limit: Int = DEFAULT_LIMIT,
        before: Long? = null,
    ): List<HistoryVersion> {
        val account = account()
        return api(account).vaultHistory(signer(account), limit, before).versions
    }

    /** [itemId] as it was after commit [version], or null if it was not live then or cannot be read. */
    suspend fun itemAt(
        version: Long,
        itemId: UUID,
    ): VaultItem? {
        val account = account()
        val past = api(account).vaultVersion(signer(account), version, itemId.toString())
        val entry = past.items.firstOrNull { it.itemId == itemId.toString() }?.takeIf { past.head.keyEpoch == account.keyEpoch }
        return entry?.let { runCatching { store.cipher().open(itemId, B64u.decode(it.blob), it.version) }.getOrNull() }
    }

    /**
     * Makes [itemId] show its content from commit [version] again, as a new edit (trash state and
     * position stay as they are now), and syncs. @return false if that version cannot be read.
     */
    suspend fun restoreVersion(
        version: Long,
        itemId: UUID,
    ): Boolean {
        val past = itemAt(version, itemId) ?: return false
        val account = account()
        val cipher = store.cipher()
        val current = store.rows().firstOrNull { it.id == itemId }?.let { runCatching { cipher.effective(it) }.getOrNull() }
        val restored =
            past.copy(
                trashed = current?.trashed ?: false,
                trashChanged = current?.trashChanged ?: 0,
                order = current?.order,
                orderChanged = current?.orderChanged ?: 0,
                updated = clock(),
                updatedBy = account.deviceId,
            )
        writePending(restored)
        engine.sync()
        return true
    }

    private suspend fun writePending(item: VaultItem) {
        val blob = store.cipher().seal(item)
        val existing = store.rows().firstOrNull { it.id == item.id }
        val row = existing?.copy(localBlob = blob, localDeleted = false, dirty = true) ?: ItemRow.pending(item.id, blob)
        store.apply(listOf(row), emptyList(), null)
    }

    private companion object {
        const val DEFAULT_LIMIT = 100
    }
}
