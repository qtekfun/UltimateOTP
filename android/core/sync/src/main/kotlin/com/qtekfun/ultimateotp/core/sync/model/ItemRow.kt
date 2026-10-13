// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import java.util.UUID

/**
 * One stored item: the server's committed state (what the signed head covers) and, when [dirty],
 * a local change not yet committed. Blobs are ciphertext (crypto-format.md §6.2); a pending local
 * blob is bound to item version 0 and re-encrypted for the commit version when it is sent.
 */
class ItemRow(
    val id: UUID,
    /** Vault version of the commit that last wrote the item; 0 if never committed. */
    val serverVersion: Long,
    val serverBlob: ByteArray?,
    val serverDeleted: Boolean,
    val localBlob: ByteArray?,
    val localDeleted: Boolean,
    val dirty: Boolean,
) {
    val onServer: Boolean get() = serverVersion > 0
    val serverLive: Boolean get() = onServer && !serverDeleted && serverBlob != null

    /** The blob the user sees: the pending change if any, else the committed one. */
    val effectiveBlob: ByteArray? get() = if (dirty) localBlob else serverBlob.takeUnless { serverDeleted }
    val effectiveDeleted: Boolean get() = if (dirty) localDeleted else serverDeleted

    fun copy(
        serverVersion: Long = this.serverVersion,
        serverBlob: ByteArray? = this.serverBlob,
        serverDeleted: Boolean = this.serverDeleted,
        localBlob: ByteArray? = this.localBlob,
        localDeleted: Boolean = this.localDeleted,
        dirty: Boolean = this.dirty,
    ) = ItemRow(id, serverVersion, serverBlob, serverDeleted, localBlob, localDeleted, dirty)

    override fun toString(): String = "ItemRow(id=$id, serverVersion=$serverVersion, dirty=$dirty, deleted=$effectiveDeleted)"

    companion object {
        /** A new item created on this device. */
        fun pending(
            id: UUID,
            blob: ByteArray,
        ) = ItemRow(id, 0, null, false, blob, false, dirty = true)
    }
}
