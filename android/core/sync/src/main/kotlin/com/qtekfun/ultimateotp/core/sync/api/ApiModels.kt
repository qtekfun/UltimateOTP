// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Models of contracts/openapi.yaml (/otp/v1, contract 1.0.0). Unknown fields are ignored.

@Serializable
data class ServerInfo(
    @SerialName("api_version") val apiVersion: String,
    @SerialName("server_time") val serverTime: Long,
)

@Serializable
data class KeyBundleDto(
    @SerialName("password_wrap") val passwordWrap: String? = null,
    @SerialName("password_kdf") val passwordKdf: String? = null,
    @SerialName("recovery_wrap") val recoveryWrap: String,
)

@Serializable
data class EnrollRequest(
    @SerialName("ed25519_public_key") val ed25519: String,
    @SerialName("x25519_public_key") val x25519: String,
    val label: String,
    val keys: KeyBundleDto? = null,
)

@Serializable
data class EnrollResponse(
    @SerialName("account_id") val accountId: String,
    val device: Device,
    val head: VaultHead,
)

@Serializable
data class EnrollmentToken(
    val token: String,
    @SerialName("expires_at") val expiresAt: Long,
)

@Serializable
data class RecoveryKeys(
    @SerialName("account_id") val accountId: String,
    @SerialName("key_epoch") val keyEpoch: Long,
    @SerialName("keys_revision") val keysRevision: Long,
    @SerialName("password_wrap") val passwordWrap: String? = null,
    @SerialName("password_kdf") val passwordKdf: String? = null,
    @SerialName("recovery_wrap") val recoveryWrap: String,
)

@Serializable
data class SealedVaultKeyDto(
    @SerialName("key_epoch") val keyEpoch: Long,
    @SerialName("sealed_vault_key") val sealedVaultKey: String,
    @SerialName("sealed_by") val sealedBy: String,
    @SerialName("seal_signature") val sealSignature: String,
)

@Serializable
data class AccountKeys(
    @SerialName("account_id") val accountId: String,
    @SerialName("key_epoch") val keyEpoch: Long,
    @SerialName("keys_revision") val keysRevision: Long,
    @SerialName("password_wrap") val passwordWrap: String? = null,
    @SerialName("password_kdf") val passwordKdf: String? = null,
    @SerialName("recovery_wrap") val recoveryWrap: String,
    @SerialName("device_key") val deviceKey: SealedVaultKeyDto? = null,
)

@Serializable
data class PutKeysRequest(
    @SerialName("base_revision") val baseRevision: Long,
    @SerialName("key_epoch") val keyEpoch: Long,
    @SerialName("password_wrap") val passwordWrap: String? = null,
    @SerialName("password_kdf") val passwordKdf: String? = null,
    @SerialName("recovery_wrap") val recoveryWrap: String,
)

@Serializable
data class Device(
    @SerialName("device_id") val deviceId: String,
    val label: String,
    @SerialName("ed25519_public_key") val ed25519: String,
    @SerialName("x25519_public_key") val x25519: String,
    @SerialName("enrolled_via") val enrolledVia: String,
    @SerialName("added_by") val addedBy: String? = null,
    @SerialName("added_by_signature") val addedBySignature: String? = null,
    @SerialName("created_at") val createdAt: Long,
    @SerialName("last_seen_at") val lastSeenAt: Long? = null,
    @SerialName("revoked_at") val revokedAt: Long? = null,
)

@Serializable
data class DeviceList(
    @SerialName("devices_revision") val devicesRevision: Long,
    val devices: List<Device>,
)

@Serializable
data class PairingCreated(
    @SerialName("pairing_id") val pairingId: String,
    val secret: String,
    @SerialName("expires_at") val expiresAt: Long,
)

@Serializable
data class PairingDevice(
    @SerialName("device_id") val deviceId: String,
    val label: String,
    @SerialName("ed25519_public_key") val ed25519: String,
    @SerialName("x25519_public_key") val x25519: String,
)

@Serializable
data class Pairing(
    @SerialName("pairing_id") val pairingId: String,
    val status: String,
    @SerialName("expires_at") val expiresAt: Long,
    val device: PairingDevice? = null,
)

@Serializable
data class JoinRequest(
    @SerialName("ed25519_public_key") val ed25519: String,
    @SerialName("x25519_public_key") val x25519: String,
    val label: String,
)

@Serializable
data class JoinResponse(
    @SerialName("pairing_id") val pairingId: String,
    @SerialName("device_id") val deviceId: String,
    val status: String,
)

@Serializable
data class ApproveRequest(
    @SerialName("device_id") val deviceId: String,
    @SerialName("device_signature") val deviceSignature: String,
    @SerialName("sealed_vault_key") val sealedVaultKey: String,
    @SerialName("seal_signature") val sealSignature: String,
)

@Serializable
data class Approver(
    @SerialName("device_id") val deviceId: String,
    @SerialName("ed25519_public_key") val ed25519: String,
)

@Serializable
data class PairingResult(
    @SerialName("pairing_id") val pairingId: String,
    val status: String,
    @SerialName("device_id") val deviceId: String,
    @SerialName("account_id") val accountId: String,
    val approver: Approver,
    @SerialName("device_signature") val deviceSignature: String? = null,
    @SerialName("device_key") val deviceKey: SealedVaultKeyDto? = null,
)

@Serializable
data class VaultHead(
    @SerialName("account_id") val accountId: String,
    val version: Long,
    @SerialName("key_epoch") val keyEpoch: Long,
    @SerialName("signed_by") val signedBy: String? = null,
    val signature: String? = null,
    @SerialName("updated_at") val updatedAt: Long? = null,
    @SerialName("rotation_required") val rotationRequired: Boolean = false,
    @SerialName("devices_revision") val devicesRevision: Long = 0,
)

@Serializable
data class HeadInput(
    val version: Long,
    val signature: String,
)

@Serializable
data class Upsert(
    @SerialName("item_id") val itemId: String,
    val blob: String,
)

@Serializable
data class CommitRequest(
    @SerialName("base_version") val baseVersion: Long,
    @SerialName("key_epoch") val keyEpoch: Long,
    val head: HeadInput,
    val upserts: List<Upsert> = emptyList(),
    val deletes: List<String> = emptyList(),
)

@Serializable
data class DeviceKeyInput(
    @SerialName("device_id") val deviceId: String,
    @SerialName("sealed_vault_key") val sealedVaultKey: String,
    @SerialName("seal_signature") val sealSignature: String,
)

@Serializable
data class RotateRequest(
    @SerialName("base_version") val baseVersion: Long,
    @SerialName("new_key_epoch") val newKeyEpoch: Long,
    val head: HeadInput,
    val upserts: List<Upsert> = emptyList(),
    val deletes: List<String> = emptyList(),
    val keys: KeyBundleDto,
    @SerialName("device_keys") val deviceKeys: List<DeviceKeyInput>,
)

@Serializable
data class Item(
    @SerialName("item_id") val itemId: String,
    val version: Long,
    val deleted: Boolean,
    val blob: String? = null,
)

@Serializable
data class VaultChanges(
    val head: VaultHead,
    val items: List<Item>,
)

@Serializable
data class EventState(
    val version: Long,
    @SerialName("key_epoch") val keyEpoch: Long,
    @SerialName("devices_revision") val devicesRevision: Long,
    @SerialName("rotation_required") val rotationRequired: Boolean,
)

@Serializable
data class Problem(
    val type: String? = null,
    val title: String? = null,
    val status: Int = 0,
    val detail: String? = null,
    val code: String = "internal_error",
    @SerialName("server_time") val serverTime: Long? = null,
    val head: VaultHead? = null,
    @SerialName("retry_after") val retryAfter: Long? = null,
)
