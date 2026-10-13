// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import com.qtekfun.ultimateotp.core.sync.model.VaultCipher
import kotlinx.serialization.Serializable
import java.util.UUID

/** A device whose Ed25519 key this client trusts for heads and sealed keys (crypto-format.md §5.2). */
@Serializable
data class PinnedDevice(
    val deviceId: String,
    val ed25519: String,
    val label: String = "",
    /** Vouched for by a pinned device (pairing certificate) or confirmed by the user here. */
    val trusted: Boolean = true,
    val revoked: Boolean = false,
)

/** Everything non-secret the client remembers about its account. */
@Serializable
data class AccountState(
    val serverUrl: String,
    val accountId: String,
    val deviceId: String,
    val label: String = "",
    /** The highest vault version whose signed head this device accepted (rollback floor). */
    val acceptedVersion: Long = 0,
    val keyEpoch: Long = 1,
    val keysRevision: Long = 1,
    val devicesRevision: Long = 0,
    val rotationRequired: Boolean = false,
    val pinned: List<PinnedDevice> = emptyList(),
    /** Server clock minus device clock, seconds (from `stale_request` or `server-info`). */
    val clockOffset: Long = 0,
) {
    fun pinnedKey(deviceId: String): String? = pinned.firstOrNull { it.deviceId == deviceId && it.trusted && !it.revoked }?.ed25519
}

/** The vault storage the sync engine works on (implemented by :core:vault with Room). */
interface SyncStore {
    suspend fun rows(): List<ItemRow>

    suspend fun account(): AccountState?

    /** Applies item changes and the new account state in one transaction. */
    suspend fun apply(
        upserts: List<ItemRow>,
        deletes: List<UUID>,
        account: AccountState?,
    )

    /** The cipher of the current vault key; throws if the vault is locked. */
    fun cipher(): VaultCipher

    /** This device's keys; throws if the vault is locked or the device has none yet. */
    fun deviceKeys(): DeviceKeys

    /** Persists device keys created for enrollment (Keystore-wrapped). */
    suspend fun saveDeviceKeys(keys: DeviceKeys)

    /**
     * Replaces the vault key (account bootstrap, enrollment, rotation). Pending local items are
     * re-encrypted for [accountId] and [keyEpoch] in the same step so nothing is lost.
     */
    suspend fun installVaultKey(
        vaultKey: ByteArray,
        keyEpoch: Long,
        accountId: String,
        account: AccountState,
    )

    /** The current vault key bytes (for wraps, seals and rotation). Caller wipes the copy. */
    fun vaultKey(): ByteArray

    /** After `device_revoked`: forget the account, keep every item as a pending local change. */
    suspend fun leaveAccount()
}
