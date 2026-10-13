// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault

import com.qtekfun.ultimateotp.core.crypto.ByteFields
import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.crypto.wipe
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.sync.SyncStore
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import com.qtekfun.ultimateotp.core.sync.model.VaultCipher
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.db.ItemEntity
import com.qtekfun.ultimateotp.core.vault.db.MetaEntity
import com.qtekfun.ultimateotp.core.vault.db.VaultDao
import com.qtekfun.ultimateotp.core.vault.secure.SecretStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import java.util.UUID

/** Where the vault is: not created yet, locked (keys not in memory) or unlocked. */
enum class VaultState { NONE, LOCKED, UNLOCKED }

/**
 * The encrypted vault: Room rows of ciphertext, the vault key in [secrets], decrypted items only
 * in memory while unlocked. Also the [SyncStore] the sync engine works on.
 */
@Suppress("TooManyFunctions")
class VaultRepository(
    private val dao: VaultDao,
    private val secrets: SecretStore,
    private val clock: () -> Long = System::currentTimeMillis,
) : SyncStore {
    private val mutex = Mutex()
    private val json = Json { ignoreUnknownKeys = true }
    private val _state = MutableStateFlow(if (secrets.contains(VAULT_KEY)) VaultState.LOCKED else VaultState.NONE)
    val state: StateFlow<VaultState> = _state.asStateFlow()

    @Volatile private var cipher: VaultCipher? = null

    @Volatile private var vaultKey: ByteArray? = null

    @Volatile private var device: DeviceKeys? = null

    /** Decrypted items, sorted for display; empty while locked. Rows that fail to decrypt are skipped. */
    val items: Flow<List<VaultItem>> =
        combine(dao.observeItems(), _state) { rows, state ->
            val c = cipher
            if (state != VaultState.UNLOCKED || c == null) {
                emptyList()
            } else {
                rows
                    .mapNotNull { e -> runCatching { c.effective(e.toRow()) }.getOrNull() }
                    .sortedWith(
                        compareByDescending<VaultItem> { it.favorite }.thenBy { it.otp.issuer.lowercase() }.thenBy {
                            it.otp.label
                                .lowercase()
                        },
                    )
            }
        }

    /** Creates an empty offline vault with a fresh key (milestone M1: no account needed). */
    suspend fun create() =
        mutex.withLock {
            check(!secrets.contains(VAULT_KEY)) { "vault exists" }
            val vk = Sodium.random(VK_BYTES)
            secrets.put(VAULT_KEY, ByteFields.u32(1) + vk)
            open(vk, 1, "")
        }

    /**
     * Loads the keys after the user authenticated (BiometricPrompt).
     * @throws com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException if not.
     */
    suspend fun unlock() =
        mutex.withLock {
            val stored = secrets.get(VAULT_KEY) ?: error("no vault")
            val epoch = ByteFields.readU32(stored, 0)
            val vk = stored.copyOfRange(Int.SIZE_BYTES, stored.size)
            stored.wipe()
            device = secrets.get(DEVICE_KEYS)?.let { s -> DeviceKeys.fromSecrets(s).also { s.wipe() } }
            open(vk, epoch, account()?.accountId.orEmpty())
        }

    private fun open(
        vk: ByteArray,
        epoch: Long,
        accountId: String,
    ) {
        vaultKey?.wipe()
        cipher?.wipe()
        vaultKey = vk
        cipher = VaultCipher(vk, accountId, epoch)
        _state.value = VaultState.UNLOCKED
    }

    /** Forgets every key in memory (app lock, timeout). */
    fun lock() {
        cipher?.wipe()
        vaultKey?.wipe()
        device?.wipe()
        cipher = null
        vaultKey = null
        device = null
        if (_state.value == VaultState.UNLOCKED) _state.value = VaultState.LOCKED
    }

    private fun requireCipher(): VaultCipher = cipher ?: error("vault is locked")

    private fun deviceId(): String = runCatchingAccount()?.deviceId ?: VaultItem.LOCAL_DEVICE

    @Volatile private var cachedAccount: AccountState? = null

    private fun runCatchingAccount(): AccountState? = cachedAccount

    // ---- editing ---------------------------------------------------------------------------

    suspend fun add(
        otp: OtpParams,
        notes: String = "",
        favorite: Boolean = false,
    ): VaultItem =
        mutex.withLock {
            val now = clock()
            val item = VaultItem(UUID.randomUUID(), otp, notes, favorite, null, now, now, deviceId())
            dao.upsert(listOf(ItemEntity.of(ItemRow.pending(item.id, requireCipher().seal(item)))))
            item
        }

    suspend fun update(item: VaultItem): VaultItem = mutex.withLock { write(item.copy(updated = clock(), updatedBy = deviceId())) }

    private suspend fun write(item: VaultItem): VaultItem {
        val blob = requireCipher().seal(item)
        val row = dao.item(item.id.toString())?.toRow()
        val next = row?.copy(localBlob = blob, localDeleted = false, dirty = true) ?: ItemRow.pending(item.id, blob)
        dao.upsert(listOf(ItemEntity.of(next)))
        return item
    }

    /** HOTP: the next code is generated from counter + 1, stored before it is shown. */
    suspend fun nextHotpCounter(id: UUID): VaultItem? =
        mutex.withLock {
            val row = dao.item(id.toString())?.toRow() ?: return@withLock null
            val item = requireCipher().effective(row) ?: return@withLock null
            write(item.copy(otp = item.otp.copy(counter = item.otp.counter + 1), updated = clock(), updatedBy = deviceId()))
        }

    suspend fun delete(id: UUID) =
        mutex.withLock {
            val row = dao.item(id.toString())?.toRow() ?: return@withLock
            if (!row.onServer) {
                dao.delete(listOf(id.toString()))
            } else {
                dao.upsert(listOf(ItemEntity.of(row.copy(localBlob = null, localDeleted = true, dirty = true))))
            }
        }

    /** Adds [accounts], skipping ones already in the vault (same type, secret, issuer and label). */
    suspend fun import(accounts: List<OtpParams>): ImportSummary =
        mutex.withLock {
            val c = requireCipher()
            val existing =
                dao
                    .items()
                    .mapNotNull { runCatching { c.effective(it.toRow()) }.getOrNull() }
                    .map { key(it.otp) }
                    .toMutableSet()
            val now = clock()
            val rows = mutableListOf<ItemEntity>()
            var duplicates = 0
            for (otp in accounts) {
                if (!existing.add(key(otp))) {
                    duplicates++
                    continue
                }
                val item = VaultItem(UUID.randomUUID(), otp, created = now, updated = now, updatedBy = deviceId())
                rows += ItemEntity.of(ItemRow.pending(item.id, c.seal(item)))
            }
            dao.upsert(rows)
            ImportSummary(added = rows.size, duplicates = duplicates)
        }

    private fun key(otp: OtpParams) = listOf(otp.type, otp.secret.toList(), otp.issuer, otp.label)

    /** Every live item, decrypted (for export). */
    suspend fun snapshot(): List<VaultItem> =
        mutex.withLock {
            val c = requireCipher()
            dao.items().mapNotNull { c.effective(it.toRow()) }
        }

    // ---- SyncStore ------------------------------------------------------------------------

    override suspend fun rows(): List<ItemRow> = dao.items().map { it.toRow() }

    override suspend fun account(): AccountState? =
        dao.meta(META_ACCOUNT)?.let { json.decodeFromString(AccountState.serializer(), it) }.also { cachedAccount = it }

    override suspend fun apply(
        upserts: List<ItemRow>,
        deletes: List<UUID>,
        account: AccountState?,
    ) {
        val meta = account?.let { listOf(MetaEntity(META_ACCOUNT, json.encodeToString(AccountState.serializer(), it))) }.orEmpty()
        dao.apply(upserts.map(ItemEntity::of), deletes.map(UUID::toString), meta)
        if (account != null) cachedAccount = account
    }

    override fun cipher(): VaultCipher = requireCipher()

    override fun deviceKeys(): DeviceKeys = device ?: error("no device keys")

    override suspend fun ensureWritable() = secrets.checkUsable()

    override suspend fun saveDeviceKeys(keys: DeviceKeys) {
        val secret = keys.exportSecrets()
        secrets.put(DEVICE_KEYS, secret)
        secret.wipe()
        device = keys
    }

    override suspend fun installVaultKey(
        vaultKey: ByteArray,
        keyEpoch: Long,
        accountId: String,
        account: AccountState,
    ) = mutex.withLock {
        val old = requireCipher()
        val next = VaultCipher(vaultKey, accountId, keyEpoch)
        // Pending items are re-encrypted for the new key and account; committed rows are
        // re-read from the server by the caller.
        val rows = dao.items().map { it.toRow() }
        val pending =
            rows.filter { it.dirty && it.localBlob != null }.map { row ->
                row.copy(localBlob = next.seal(old.open(row.id, row.localBlob!!)))
            }
        secrets.put(VAULT_KEY, ByteFields.u32(keyEpoch) + vaultKey)
        apply(pending, emptyList(), account)
        open(vaultKey.copyOf(), keyEpoch, accountId)
    }

    override fun vaultKey(): ByteArray = vaultKey?.copyOf() ?: error("vault is locked")

    /** Forgets the account (after `device_revoked`): keeps the items, all pending again. */
    override suspend fun leaveAccount() =
        mutex.withLock {
            val c = requireCipher()
            val local = VaultCipher(vaultKey(), "", c.keyEpoch)
            val rows =
                dao.items().map { it.toRow() }.mapNotNull { row ->
                    val item = c.effective(row) ?: return@mapNotNull null
                    ItemRow.pending(row.id, local.seal(item))
                }
            dao.deleteAllItems()
            dao.upsert(rows.map(ItemEntity::of))
            dao.deleteMeta(META_ACCOUNT)
            secrets.delete(DEVICE_KEYS)
            cachedAccount = null
            device = null
            open(vaultKey(), c.keyEpoch, "")
        }

    companion object {
        const val VAULT_KEY = "vault_key"
        const val DEVICE_KEYS = "device_keys"
        const val META_ACCOUNT = "account"
        private const val VK_BYTES = 32
    }
}

data class ImportSummary(
    val added: Int,
    val duplicates: Int,
    val rejected: Int = 0,
)
