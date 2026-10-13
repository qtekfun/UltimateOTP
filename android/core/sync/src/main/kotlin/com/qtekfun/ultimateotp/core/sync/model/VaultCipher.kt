// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import com.qtekfun.ultimateotp.core.crypto.ItemBinding
import com.qtekfun.ultimateotp.core.crypto.ItemCipher
import java.util.UUID

/**
 * Encrypts and decrypts items for one vault key: [accountId] is "" while the vault has no
 * account (crypto-format.md §6.2). Pending (uncommitted) blobs use item version 0.
 */
class VaultCipher(
    vaultKey: ByteArray,
    val accountId: String,
    val keyEpoch: Long,
) {
    private val itemKey = ItemCipher.itemKey(vaultKey)

    fun seal(
        item: VaultItem,
        version: Long = PENDING,
    ): ByteArray = ItemCipher.encrypt(itemKey, ItemBinding(accountId, item.id, version, keyEpoch), ItemCodec.encode(item))

    fun open(
        id: UUID,
        blob: ByteArray,
        version: Long = PENDING,
    ): VaultItem = ItemCodec.decode(id, ItemCipher.decrypt(itemKey, ItemBinding(accountId, id, version, keyEpoch), blob))

    /** The item a row shows, or null if it is deleted. */
    fun effective(row: ItemRow): VaultItem? {
        val blob = row.effectiveBlob ?: return null
        return if (row.dirty) open(row.id, blob) else open(row.id, blob, row.serverVersion)
    }

    /** The server's committed item of a row, or null. */
    fun committed(row: ItemRow): VaultItem? = row.serverBlob?.takeIf { row.serverLive }?.let { open(row.id, it, row.serverVersion) }

    fun wipe() = itemKey.fill(0)

    companion object {
        const val PENDING = 0L
    }
}
