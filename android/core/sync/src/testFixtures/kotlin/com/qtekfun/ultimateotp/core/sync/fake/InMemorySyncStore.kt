// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.fake

import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.sync.SyncStore
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import com.qtekfun.ultimateotp.core.sync.model.VaultCipher
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import java.util.UUID

/** A [SyncStore] in memory with the same rules as the Room vault: one simulated device in tests. */
class InMemorySyncStore(
    private val clock: () -> Long = { 1_000L },
) : SyncStore {
    private val rows = linkedMapOf<UUID, ItemRow>()
    private var account: AccountState? = null
    private var vaultKey = Sodium.random(VK_BYTES)
    private var cipher = VaultCipher(vaultKey, "", 1)
    private var keys: DeviceKeys? = null

    override suspend fun rows(): List<ItemRow> = rows.values.toList()

    override suspend fun account(): AccountState? = account

    override suspend fun apply(
        upserts: List<ItemRow>,
        deletes: List<UUID>,
        account: AccountState?,
    ) {
        upserts.forEach { rows[it.id] = it }
        deletes.forEach { rows.remove(it) }
        if (account != null) this.account = account
    }

    /**
     * When set, secrets cannot be written, like a Keystore key whose authentication lapsed or
     * that was invalidated: [ensureWritable], [saveDeviceKeys] and [installVaultKey] throw it.
     */
    @Volatile var refuseSecrets: Exception? = null

    override suspend fun ensureWritable() {
        refuseSecrets?.let { throw it }
    }

    override fun cipher(): VaultCipher = cipher

    override fun deviceKeys(): DeviceKeys = keys ?: error("no device keys")

    override suspend fun saveDeviceKeys(keys: DeviceKeys) {
        ensureWritable()
        this.keys = keys
    }

    override suspend fun installVaultKey(
        vaultKey: ByteArray,
        keyEpoch: Long,
        accountId: String,
        account: AccountState,
    ) {
        ensureWritable()
        val next = VaultCipher(vaultKey, accountId, keyEpoch)
        rows.replaceAll { _, row ->
            if (row.dirty && row.localBlob != null) row.copy(localBlob = next.seal(cipher.open(row.id, row.localBlob))) else row
        }
        this.vaultKey = vaultKey.copyOf()
        cipher = next
        this.account = account
    }

    override fun vaultKey(): ByteArray = vaultKey.copyOf()

    override suspend fun leaveAccount() {
        val local = VaultCipher(vaultKey, "", cipher.keyEpoch)
        val items = rows.values.mapNotNull { row -> cipher.effective(row)?.let { ItemRow.pending(row.id, local.seal(it)) } }
        rows.clear()
        items.forEach { rows[it.id] = it }
        cipher = local
        account = null
        keys = null
    }

    // ---- editing like VaultRepository ---------------------------------------------------------

    fun deviceId(): String = account?.deviceId ?: VaultItem.LOCAL_DEVICE

    fun add(otp: OtpParams): VaultItem {
        val item = VaultItem(UUID.randomUUID(), otp, created = clock(), updated = clock(), updatedBy = deviceId())
        rows[item.id] = ItemRow.pending(item.id, cipher.seal(item))
        return item
    }

    fun update(item: VaultItem) {
        val next = item.copy(updated = clock(), updatedBy = deviceId())
        val row = rows[item.id]
        val blob = cipher.seal(next)
        rows[item.id] = row?.copy(localBlob = blob, localDeleted = false, dirty = true) ?: ItemRow.pending(item.id, blob)
    }

    /** Writes [item] as it is, without touching `updated`: a trash or reorder change, not an edit. */
    fun put(item: VaultItem) {
        val row = rows[item.id]
        val blob = cipher.seal(item)
        rows[item.id] = row?.copy(localBlob = blob, localDeleted = false, dirty = true) ?: ItemRow.pending(item.id, blob)
    }

    fun delete(id: UUID) {
        val row = rows[id] ?: return
        if (!row.onServer) rows.remove(id) else rows[id] = row.copy(localBlob = null, localDeleted = true, dirty = true)
    }

    fun items(): List<VaultItem> = rows.values.mapNotNull { cipher.effective(it) }.sortedBy { it.otp.label }

    private companion object {
        const val VK_BYTES = 32
    }
}
