// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.crypto.B64u
import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.crypto.Ed25519
import com.qtekfun.ultimateotp.core.crypto.KdfParams
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.crypto.RecoveryKey
import com.qtekfun.ultimateotp.core.crypto.Sas
import com.qtekfun.ultimateotp.core.crypto.SealedVaultKey
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.crypto.Srp
import com.qtekfun.ultimateotp.core.crypto.Statements
import com.qtekfun.ultimateotp.core.crypto.VaultKeyWraps
import com.qtekfun.ultimateotp.core.crypto.wipe
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.api.ApproveRequest
import com.qtekfun.ultimateotp.core.sync.api.CommitRequest
import com.qtekfun.ultimateotp.core.sync.api.DeviceKeyInput
import com.qtekfun.ultimateotp.core.sync.api.EnrollRequest
import com.qtekfun.ultimateotp.core.sync.api.EnrollResponse
import com.qtekfun.ultimateotp.core.sync.api.HeadInput
import com.qtekfun.ultimateotp.core.sync.api.JoinRequest
import com.qtekfun.ultimateotp.core.sync.api.KeyBundleDto
import com.qtekfun.ultimateotp.core.sync.api.NewDevice
import com.qtekfun.ultimateotp.core.sync.api.PairingDevice
import com.qtekfun.ultimateotp.core.sync.api.PutKeysRequest
import com.qtekfun.ultimateotp.core.sync.api.RotateRequest
import com.qtekfun.ultimateotp.core.sync.api.SessionInfo
import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.SignupRequest
import com.qtekfun.ultimateotp.core.sync.api.SrpAttributes
import com.qtekfun.ultimateotp.core.sync.api.SrpSessionRequest
import com.qtekfun.ultimateotp.core.sync.api.SrpSetupDto
import com.qtekfun.ultimateotp.core.sync.api.SrpVerifyRequest
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.api.Upsert
import com.qtekfun.ultimateotp.core.sync.api.VaultChanges
import com.qtekfun.ultimateotp.core.sync.api.VaultHead
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import com.qtekfun.ultimateotp.core.sync.model.Merge
import com.qtekfun.ultimateotp.core.sync.model.VaultCipher
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.UUID

/** Outcome of one sync round. */
sealed interface SyncResult {
    data class Synced(
        val version: Long,
        val committed: Int,
        val conflicts: Int,
    ) : SyncResult

    /** The server's state failed verification (rollback, unknown signer, wrong manifest). Local data kept. */
    data class Rejected(
        val reason: String,
    ) : SyncResult

    /** This device was revoked; the account was forgotten, items kept locally. */
    data object Revoked : SyncResult

    data object NoAccount : SyncResult
}

/** The server state could not be trusted (crypto-format.md §7). */
class HeadRejectedException(
    reason: String,
) : Exception(reason)

/** What the joining device shows while it waits for approval. */
data class JoinedPairing(
    val link: PairLink,
    val deviceId: String,
    val sasWords: List<String>,
)

/** A device of the account as the UI shows it. */
data class DeviceView(
    val deviceId: String,
    val label: String,
    val trusted: Boolean,
    val revoked: Boolean,
    val isThisDevice: Boolean,
)

/**
 * The client side of sync (design.md §4.4, crypto-format.md §5-§8): account bootstrap, enrollment
 * with the password or recovery key, pairing, pull with head verification and per-item merge,
 * optimistic commits, device trust, revocation and key rotation.
 */
@Suppress("TooManyFunctions", "LargeClass")
class SyncEngine(
    private val store: SyncStore,
    private val apiFor: (String) -> UotpApi,
    private val kdfLadder: () -> List<Pair<Long, Long>> = { PasswordKdf.SENSITIVE_LADDER },
) {
    private val mutex = Mutex()

    private fun signer(account: AccountState) = Signer(store.deviceKeys(), account.deviceId)

    // ---- account bootstrap and enrollment ----------------------------------------------------

    /**
     * The keys of a new account, made on this device before anything is sent: this offline
     * vault's key wrapped for a new recovery key and, when there is one, the password, with the
     * SRP login record (crypto-format.md §4, §4.4). Only wraps leave the device.
     */
    class NewAccountKeys internal constructor(
        val bundle: KeyBundleDto,
        /** The 24-word recovery key (decision 10), to show once. */
        val recoveryWords: List<String>,
    )

    /** Fails now if the store would refuse to save keys (see [SyncStore.ensureWritable]). */
    suspend fun preflight() = store.ensureWritable()

    /** Wraps this offline vault's key for a new account (slow with a password: Argon2id). */
    fun newAccountKeys(password: String?): NewAccountKeys {
        val vk = store.vaultKey()
        val rk = RecoveryKey.generate()
        val kekRk = VaultKeyWraps.recoveryKek(rk)
        val derived = password?.let { PasswordKdf.deriveNew(it, kdfLadder()) }
        try {
            val bundle = VaultKeyWraps.bundle(vk, FIRST_EPOCH, kekRk, derived?.second, derived?.first)
            // The SRP login record (crypto-format.md §4.4) goes with the password wraps.
            val srp =
                derived
                    ?.second
                    ?.let { kek -> Srp.setup(kek) }
                    ?.let { SrpSetupDto(it.srpUserId, B64u.encode(it.salt), B64u.encode(it.verifier)) }
            return NewAccountKeys(bundle.toDto().copy(srp = srp), RecoveryKey.toWords(rk))
        } finally {
            vk.wipe()
            rk.wipe()
            kekRk.wipe()
            derived?.second?.wipe()
        }
    }

    /**
     * First device of a new account: turns this offline vault into the account's vault. Its vault
     * key becomes epoch 1, wrapped for the password (if any) and a new recovery key.
     * @return the 24 recovery words, to show once.
     */
    suspend fun bootstrap(
        serverUrl: String,
        token: String,
        password: String?,
        label: String,
        emailCode: String? = null,
    ): List<String> =
        mutex.withLock {
            store.ensureWritable()
            val api = apiFor(serverUrl)
            val created = newAccountKeys(password)
            val keys = DeviceKeys.generate()
            store.ensureWritable() // again: the key derivation above took seconds
            val request =
                EnrollRequest(keys.ed25519PublicB64u, keys.x25519PublicB64u, label, created.bundle, api.appVersion, emailCode)
            val response = api.enroll(token, Signer(keys, UotpApi.PENDING), request)
            adoptNewAccount(api, serverUrl, keys, response, label)
            created.recoveryWords
        }

    /**
     * Public sign-up (`POST /otp/v1/signup`, contract 1.1.0, like Ente Auth): creates the account
     * from this offline vault with [created] (made by [newAccountKeys] with a password) and
     * registers this device, proving possession of its new key (`X-UOTP-Device: pending`).
     * Local items stay pending; the next [sync] uploads them as the initial vault.
     */
    suspend fun signup(
        serverUrl: String,
        email: String,
        emailCode: String?,
        created: NewAccountKeys,
        label: String,
    ) = mutex.withLock {
        check(store.account() == null) { "this device already has an account" }
        requireNotNull(created.bundle.srp) { "sign-up needs a password" }
        // The server answers 201 once; a local failure after that would orphan the account.
        store.ensureWritable()
        val api = apiFor(serverUrl)
        val keys = DeviceKeys.generate()
        val request =
            SignupRequest(
                email = email,
                emailCode = emailCode,
                device = NewDevice(keys.ed25519PublicB64u, keys.x25519PublicB64u, label, api.appVersion),
                keys = created.bundle,
            )
        val response = api.signup(Signer(keys, UotpApi.PENDING), request)
        adoptNewAccount(api, serverUrl, keys, response, label)
    }

    /** Bootstrap and sign-up: this device's keys and this vault's key become the account's (epoch 1). */
    private suspend fun adoptNewAccount(
        api: UotpApi,
        serverUrl: String,
        keys: DeviceKeys,
        response: EnrollResponse,
        label: String,
    ) {
        store.saveDeviceKeys(keys)
        val account =
            AccountState(
                serverUrl = serverUrl,
                accountId = response.accountId,
                deviceId = response.device.deviceId,
                label = label,
                keyEpoch = FIRST_EPOCH,
                devicesRevision = response.head.devicesRevision,
                pinned = listOf(PinnedDevice(response.device.deviceId, keys.ed25519PublicB64u, label)),
                clockOffset = api.clockOffset,
            )
        val vk = store.vaultKey()
        try {
            store.installVaultKey(vk, FIRST_EPOCH, response.accountId, account)
        } finally {
            vk.wipe()
        }
    }

    /** New or reinstalled device without another device at hand: password path (enrollment token). */
    suspend fun enrollWithPassword(
        serverUrl: String,
        token: String,
        password: String,
        label: String,
    ) = enrollWithKeys(serverUrl, token, label) { keys ->
        val wraps = requireNotNull(keys.passwordWrap) { "the account has no password path" }
        VaultKeyWraps.openWithPassword(password, wraps, requireNotNull(keys.passwordKdf), keys.keyEpoch).vaultKey
    }

    suspend fun enrollWithRecoveryKey(
        serverUrl: String,
        token: String,
        words: String,
        label: String,
    ) = enrollWithKeys(serverUrl, token, label) { keys ->
        VaultKeyWraps.openWithRecoveryKey(RecoveryKey.fromWords(words), keys.recoveryWrap, keys.keyEpoch)
    }

    private suspend fun enrollWithKeys(
        serverUrl: String,
        token: String,
        label: String,
        unwrap: (com.qtekfun.ultimateotp.core.sync.api.RecoveryKeys) -> ByteArray,
    ) = mutex.withLock {
        store.ensureWritable()
        val api = apiFor(serverUrl)
        val wraps = api.recoveryKeys(token)
        val vk = unwrap(wraps)
        var writable = false
        try {
            store.ensureWritable() // again: unwrapping with a password took seconds
            writable = true
        } finally {
            if (!writable) vk.wipe()
        }
        val keys = DeviceKeys.generate()
        val response = api.enroll(token, Signer(keys, UotpApi.PENDING), EnrollRequest(keys.ed25519PublicB64u, keys.x25519PublicB64u, label))
        store.saveDeviceKeys(keys)
        // Trust on first use: the device list found at enrollment (crypto-format.md §5.2).
        val devices = api.devices(Signer(keys, response.device.deviceId)).devices
        val account =
            AccountState(
                serverUrl = serverUrl,
                accountId = response.accountId,
                deviceId = response.device.deviceId,
                label = label,
                keyEpoch = wraps.keyEpoch,
                keysRevision = wraps.keysRevision,
                pinned = devices.filter { it.revokedAt == null }.map { PinnedDevice(it.deviceId, it.ed25519, it.label) },
                clockOffset = api.clockOffset,
            )
        store.installVaultKey(vk, wraps.keyEpoch, response.accountId, account)
        vk.wipe()
    }

    /** What `/srp/session` returned, plus our private ephemeral (memory only). */
    class SrpHandshake(
        val email: String,
        val attributes: SrpAttributes,
        val sessionId: String,
        val serverB: ByteArray,
        val privateA: ByteArray,
    )

    /** Login step 4 (contract 1.1.0): starts an SRP session; checks the emailed code if one is required. */
    suspend fun startSrp(
        serverUrl: String,
        email: String,
        attributes: SrpAttributes,
        emailCode: String?,
    ): SrpHandshake {
        val privateA = Sodium.random(SRP_PRIVATE_BYTES)
        val session = Srp.start(ByteArray(KEY_BYTES), attributes.srpUserId, B64u.decode(attributes.srpSalt), privateA = privateA)
        val started = apiFor(serverUrl).srpSession(SrpSessionRequest(email, B64u.encode(session.publicA), emailCode?.ifBlank { null }))
        return SrpHandshake(email, attributes, started.sessionId, B64u.decode(started.srpB), privateA)
    }

    /**
     * Login step 5: proves the password, checks the server's proof, unwraps the vault key and
     * registers this device. @throws CryptoException.AuthenticationFailed for a wrong password.
     */
    suspend fun completeSrp(
        serverUrl: String,
        handshake: SrpHandshake,
        password: String,
        label: String,
    ) = mutex.withLock {
        val api = apiFor(serverUrl)
        val params = KdfParams.decode(B64u.decode(handshake.attributes.passwordKdf)).checkReaderLimits()
        val kek = PasswordKdf.derive(password, params)
        try {
            val session =
                Srp.start(
                    kek,
                    handshake.attributes.srpUserId,
                    B64u.decode(handshake.attributes.srpSalt),
                    privateA = handshake.privateA,
                )
            val m1 = session.proof(handshake.serverB)
            // After the slow key derivation, right before the request that registers this device.
            store.ensureWritable()
            val keys = DeviceKeys.generate()
            val login =
                try {
                    api.srpVerify(
                        Signer(keys, UotpApi.PENDING),
                        SrpVerifyRequest(
                            handshake.sessionId,
                            B64u.encode(m1),
                            NewDevice(keys.ed25519PublicB64u, keys.x25519PublicB64u, label, api.appVersion),
                        ),
                    )
                } catch (e: ApiException) {
                    if (e.code == "srp_failed") throw CryptoException.AuthenticationFailed("wrong password")
                    throw e
                }
            if (!session.verifyServer(B64u.decode(login.srpM2))) reject("the server did not prove it knows the verifier")
            val wrap = login.keys.passwordWrap ?: reject("no password wrap")
            val vk = VaultKeyWraps.openWithKek(kek, wrap, params, login.keys.keyEpoch).vaultKey
            store.saveDeviceKeys(keys)
            val devices = api.devices(Signer(keys, login.device.deviceId)).devices
            val account =
                AccountState(
                    serverUrl = serverUrl,
                    accountId = login.accountId,
                    deviceId = login.device.deviceId,
                    label = label,
                    keyEpoch = login.keys.keyEpoch,
                    keysRevision = login.keys.keysRevision,
                    // Trust on first use, flagged like password enrollment (crypto-format.md §5.2).
                    pinned = devices.filter { it.revokedAt == null }.map { PinnedDevice(it.deviceId, it.ed25519, it.label) },
                    clockOffset = api.clockOffset,
                )
            store.installVaultKey(vk, login.keys.keyEpoch, login.accountId, account)
            vk.wipe()
        } finally {
            kek.wipe()
        }
    }

    /**
     * Sets a new master password (`PUT /otp/v1/account/keys`): new kind 1 and 3 wraps and a new SRP
     * record. Proves knowledge of the account with the current password or the 24 recovery words
     * (the path after recovering with the recovery key).
     */
    suspend fun changePassword(
        newPassword: String,
        currentPassword: String?,
        recoveryWords: String?,
    ) = mutex.withLock {
        val account = requireAccount()
        val api = api(account)
        val keys = api.accountKeys(signer(account))
        val (oldKek, _, kekRk) = rotationKeks(keys, currentPassword, recoveryWords)
        oldKek?.wipe()
        val (params, kek) = PasswordKdf.deriveNew(newPassword, kdfLadder())
        val vk = store.vaultKey()
        try {
            val bundle = VaultKeyWraps.bundle(vk, account.keyEpoch, kekRk, kek, params)
            val srp = Srp.setup(kek)
            val updated =
                api.putAccountKeys(
                    signer(account),
                    PutKeysRequest(
                        baseRevision = keys.keysRevision,
                        keyEpoch = keys.keyEpoch,
                        passwordWrap = bundle.passwordWrap,
                        passwordKdf = bundle.passwordKdf,
                        recoveryWrap = bundle.recoveryWrap,
                        srp = SrpSetupDto(srp.srpUserId, B64u.encode(srp.salt), B64u.encode(srp.verifier)),
                    ),
                )
            store.apply(emptyList(), emptyList(), account.copy(keysRevision = updated.keysRevision))
        } finally {
            vk.wipe()
            kek.wipe()
            kekRk.wipe()
        }
    }

    /** Session metadata for the "Active sessions" screen (decision 9). */
    suspend fun sessions(): List<SessionInfo> {
        val account = requireAccount()
        return api(account).sessions(signer(account)).sessions
    }

    // ---- pairing ------------------------------------------------------------------------------

    /** Existing device: opens a pairing session; show [PairLink.format] as a QR code. */
    suspend fun startPairing(): PairLink {
        val account = requireAccount()
        val api = api(account)
        val created = api.createPairing(signer(account))
        return PairLink(api.baseUrl, created.pairingId, created.secret, store.deviceKeys().ed25519PublicB64u)
    }

    /** Existing device: the joined device and the six words to compare, or null while nobody joined. */
    suspend fun pairingCandidate(pairingId: String): Pair<PairingDevice, List<String>>? {
        val account = requireAccount()
        val pairing = api(account).pairing(signer(account), pairingId)
        val device = pairing.device ?: return null
        val words = Sas.words(store.deviceKeys().ed25519Public, B64u.decode(device.ed25519), B64u.decode(device.x25519))
        return device to words
    }

    /** Existing device, after the user saw matching words: certify the device and seal the vault key to it. */
    suspend fun approvePairing(
        pairingId: String,
        device: PairingDevice,
    ) = mutex.withLock {
        val account = requireAccount()
        val keys = store.deviceKeys()
        val certificate = keys.signB64u(Statements.device(account.accountId, device.deviceId, device.ed25519, device.x25519))
        val vk = store.vaultKey()
        val sealed = SealedVaultKey.seal(vk, account.keyEpoch, account.accountId, B64u.decode(device.x25519))
        vk.wipe()
        val sealSignature = keys.signB64u(Statements.seal(account.accountId, account.keyEpoch, device.deviceId, sealed))
        api(account).approve(signer(account), pairingId, ApproveRequest(device.deviceId, certificate, B64u.encode(sealed), sealSignature))
        store.apply(
            emptyList(),
            emptyList(),
            account.copy(
                pinned =
                    account.pinned + PinnedDevice(device.deviceId, device.ed25519, device.label),
            ),
        )
    }

    suspend fun rejectPairing(pairingId: String) {
        val account = requireAccount()
        api(account).reject(signer(account), pairingId)
    }

    /** New device: joins the session of [link]; show the returned words. */
    suspend fun joinPairing(
        link: PairLink,
        label: String,
    ): JoinedPairing {
        val keys = DeviceKeys.generate()
        store.saveDeviceKeys(keys)
        val joined =
            apiFor(link.server).join(
                link.secret,
                Signer(keys, UotpApi.PENDING),
                link.pairingId,
                JoinRequest(keys.ed25519PublicB64u, keys.x25519PublicB64u, label),
            )
        val words = Sas.words(B64u.decode(link.approverEd25519), keys.ed25519Public, keys.x25519Public)
        return JoinedPairing(link, joined.deviceId, words)
    }

    /**
     * New device: polls until the session is decided. On approval verifies the approver against
     * the QR key, the certificate and the seal signature, then adopts the vault key.
     * @return true if approved, false if rejected or expired.
     */
    suspend fun awaitPairing(
        joined: JoinedPairing,
        label: String,
        pollMillis: Long = POLL_MS,
    ): Boolean {
        val keys = store.deviceKeys()
        val api = apiFor(joined.link.server)
        while (true) {
            val result = api.pairingResult(joined.link.secret, Signer(keys, joined.deviceId), joined.link.pairingId)
            when (result.status) {
                "approved" -> {
                    adoptPairing(joined, label, keys, result)
                    return true
                }

                "rejected", "expired" -> {
                    return false
                }

                else -> {
                    delay(pollMillis)
                }
            }
        }
    }

    private suspend fun adoptPairing(
        joined: JoinedPairing,
        label: String,
        keys: DeviceKeys,
        result: com.qtekfun.ultimateotp.core.sync.api.PairingResult,
    ) = mutex.withLock {
        val approverKey = result.approver.ed25519
        if (approverKey != joined.link.approverEd25519) reject("approver key differs from the QR code")
        val cert = Statements.device(result.accountId, joined.deviceId, keys.ed25519PublicB64u, keys.x25519PublicB64u)
        val sealed = requireNotNull(result.deviceKey) { "approved without a sealed key" }
        val sealedBytes = B64u.decode(sealed.sealedVaultKey)
        val sealMessage = Statements.seal(result.accountId, sealed.keyEpoch, joined.deviceId, sealedBytes)
        if (!Ed25519.verifyB64u(approverKey, cert, result.deviceSignature.orEmpty()) ||
            !Ed25519.verifyB64u(approverKey, sealMessage, sealed.sealSignature)
        ) {
            reject("pairing signatures do not verify")
        }
        val vk = SealedVaultKey.open(keys, sealedBytes, sealed.keyEpoch, result.accountId)
        val account =
            AccountState(
                serverUrl = joined.link.server,
                accountId = result.accountId,
                deviceId = joined.deviceId,
                label = label,
                keyEpoch = sealed.keyEpoch,
                pinned =
                    listOf(
                        PinnedDevice(joined.deviceId, keys.ed25519PublicB64u, label),
                        PinnedDevice(result.approver.deviceId, approverKey),
                    ),
            )
        store.installVaultKey(vk, sealed.keyEpoch, result.accountId, account)
        vk.wipe()
    }

    // ---- sync ---------------------------------------------------------------------------------

    /** Pull, verify, merge, then commit local changes (retrying on `409`). */
    suspend fun sync(): SyncResult =
        mutex.withLock {
            val start = store.account() ?: return@withLock SyncResult.NoAccount
            try {
                var conflicts = pull(start)
                var committed = 0
                repeat(MAX_COMMIT_ATTEMPTS) {
                    when (val outcome = push(requireAccount())) {
                        is Push.Done -> {
                            committed = outcome.count
                            return@withLock SyncResult.Synced(requireAccount().acceptedVersion, committed, conflicts)
                        }

                        Push.Conflict -> {
                            conflicts += pull(requireAccount())
                        }
                    }
                }
                SyncResult.Synced(requireAccount().acceptedVersion, committed, conflicts)
            } catch (e: HeadRejectedException) {
                SyncResult.Rejected(e.message.orEmpty())
            } catch (e: ApiException) {
                if (e.code == "device_revoked") {
                    store.leaveAccount()
                    SyncResult.Revoked
                } else {
                    throw e
                }
            }
        }

    /** @return the number of edit/edit conflicts that produced a copy. */
    private suspend fun pull(account: AccountState): Int {
        val api = api(account)
        val changes = api.vault(signer(account), account.acceptedVersion)
        var current = account
        if (changes.head.keyEpoch != current.keyEpoch) current = adoptRotatedKey(current, api)
        val rows = store.rows().associateBy { it.id }.toMutableMap()
        val cipher = store.cipher()
        // The server's view after the changes, before merging local edits.
        val server = rows.mapValues { it.value }.toMutableMap()
        for (item in changes.items) {
            val id = UUID.fromString(item.itemId)
            val blob = item.blob?.let(B64u::decode)
            val base = server[id] ?: ItemRow(id, 0, null, false, null, false, false)
            server[id] =
                base.copy(serverVersion = item.version, serverBlob = if (item.deleted) null else blob, serverDeleted = item.deleted)
        }
        // A full answer lists every live item: one we hold that is missing is gone (its tombstone
        // was compacted away), whether or not the server still sends the tombstone.
        val vanished = vanishedIds(changes, rows.values)
        vanished.forEach { server[it] = server.getValue(it).copy(serverBlob = null, serverDeleted = true) }
        current = verifyHead(changes.head, server.values, current, api)
        var conflicts = 0
        val upserts = mutableListOf<ItemRow>()
        for (id in changes.items.map { UUID.fromString(it.itemId) } + vanished) {
            val next = server.getValue(id)
            val local = rows[id]
            if (local == null || !local.dirty) {
                upserts += next.copy(localBlob = null, localDeleted = false, dirty = false)
                continue
            }
            val (rows2, copies) = mergeLocal(local, next, cipher)
            upserts += rows2
            conflicts += copies
        }
        val accepted =
            current.copy(
                acceptedVersion = changes.head.version,
                rotationRequired = changes.head.rotationRequired,
                devicesRevision = changes.head.devicesRevision,
            )
        store.apply(upserts, emptyList(), accepted)
        return conflicts
    }

    /** Merges one pending local change with the server's new state of the item: the rows to store, and the copies made. */
    private fun mergeLocal(
        local: ItemRow,
        next: ItemRow,
        cipher: VaultCipher,
    ): Pair<List<ItemRow>, Int> {
        val mine = if (local.localDeleted) null else local.localBlob?.let { cipher.open(local.id, it) }
        val merged = Merge.resolve(mine, cipher.committed(next), base = cipher.committed(local))
        val row =
            if (merged.dirty && merged.item != null) {
                next.copy(localBlob = cipher.seal(merged.item), localDeleted = false, dirty = true)
            } else {
                next.copy(localBlob = null, localDeleted = false, dirty = false)
            }
        val copy = merged.conflictCopy?.let { ItemRow.pending(it.id, cipher.seal(it)) }
        return listOfNotNull(row, copy) to (if (copy != null) 1 else 0)
    }

    /** On a `full` answer: the live items we hold that the server no longer lists. */
    private fun vanishedIds(
        changes: VaultChanges,
        rows: Collection<ItemRow>,
    ): List<UUID> {
        if (!changes.full) return emptyList()
        val listed = changes.items.mapTo(mutableSetOf()) { UUID.fromString(it.itemId) }
        return rows.filter { it.serverLive && it.id !in listed }.map { it.id }
    }

    /** crypto-format.md §7: pinned signer, signature, manifest, no rollback. */
    private suspend fun verifyHead(
        head: VaultHead,
        server: Collection<ItemRow>,
        account: AccountState,
        api: UotpApi,
    ): AccountState {
        if (head.accountId != account.accountId) reject("head of another account")
        if (head.version <
            account.acceptedVersion
        ) {
            reject("rollback: version ${head.version} < ${account.acceptedVersion}")
        }
        val live = server.filter { it.serverLive }
        if (head.version == 0L) {
            if (account.acceptedVersion != 0L || live.isNotEmpty()) reject("unsigned head")
            return account
        }
        val signedBy = head.signedBy ?: reject("unsigned head")
        var current = account
        if (current.pinnedKey(signedBy) == null) current = refreshDevices(current, api)
        val key = current.pinnedKey(signedBy) ?: reject("head signed by an untrusted device")
        val manifest = Statements.manifest(live.map { Statements.ManifestEntry(it.id.toString(), it.serverVersion, it.serverBlob!!) })
        val message = Statements.head(head.accountId, head.version, head.keyEpoch, signedBy, manifest)
        if (!Ed25519.verifyB64u(key, message, head.signature.orEmpty())) reject("bad head signature or manifest")
        return current
    }

    private sealed interface Push {
        data class Done(
            val count: Int,
        ) : Push

        data object Conflict : Push
    }

    @Suppress("LongMethod", "ReturnCount") // One commit: build, sign, send, record.
    private suspend fun push(account: AccountState): Push {
        val rows = store.rows()
        val dirty = rows.filter { it.dirty }
        // Deleted before ever reaching the server: nothing to commit.
        val localOnlyDeletes = dirty.filter { it.localDeleted && !it.onServer }.map { it.id }
        if (localOnlyDeletes.isNotEmpty()) store.apply(emptyList(), localOnlyDeletes, null)
        val toSend = dirty.filterNot { it.id in localOnlyDeletes }
        if (toSend.isEmpty()) return Push.Done(0)
        val cipher = store.cipher()
        val version = account.acceptedVersion + 1
        val upserted =
            toSend
                .filter { !it.localDeleted && it.localBlob != null }
                .associate { it.id to cipher.seal(cipher.open(it.id, it.localBlob!!), version) }
        val deleted = toSend.filter { it.localDeleted }.map { it.id }
        val manifest =
            Statements.manifest(
                rows
                    .filter { it.serverLive && it.id !in upserted && it.id !in deleted }
                    .map { Statements.ManifestEntry(it.id.toString(), it.serverVersion, it.serverBlob!!) } +
                    upserted.map { (id, blob) -> Statements.ManifestEntry(id.toString(), version, blob) },
            )
        val keys = store.deviceKeys()
        val signature = keys.signB64u(Statements.head(account.accountId, version, account.keyEpoch, account.deviceId, manifest))
        val request =
            CommitRequest(
                baseVersion = account.acceptedVersion,
                keyEpoch = account.keyEpoch,
                head = HeadInput(version, signature),
                upserts = upserted.map { (id, blob) -> Upsert(id.toString(), B64u.encode(blob)) },
                deletes = deleted.map(UUID::toString),
            )
        try {
            api(account).commit(signer(account), request)
        } catch (e: ApiException) {
            if (e.code == "version_conflict" || e.code == "key_epoch_conflict") return Push.Conflict
            throw e
        }
        val committed = toSend.associateBy { it.id }
        val updates =
            upserted.map { (id, blob) ->
                committed
                    .getValue(
                        id,
                    ).copy(serverVersion = version, serverBlob = blob, serverDeleted = false, localBlob = null, dirty = false)
            } +
                deleted.map { id ->
                    committed
                        .getValue(
                            id,
                        ).copy(
                            serverVersion = version,
                            serverBlob = null,
                            serverDeleted = true,
                            localBlob = null,
                            localDeleted = false,
                            dirty = false,
                        )
                }
        store.apply(updates, emptyList(), account.copy(acceptedVersion = version))
        return Push.Done(toSend.size)
    }

    /**
     * Decision 12: after the server was restored from an old backup its head is older than ours
     * and every pull is refused. This re-seeds it: our accepted state is forgotten and every item
     * we hold is committed again on top of whatever the server now has.
     */
    suspend fun uploadLocalCopy(): SyncResult {
        mutex.withLock {
            val account = requireAccount()
            val cipher = store.cipher()
            val rows =
                store.rows().mapNotNull { row ->
                    val item = cipher.effective(row) ?: return@mapNotNull null
                    ItemRow.pending(row.id, cipher.seal(item))
                }
            val ids = store.rows().map { it.id }
            store.apply(emptyList(), ids, null)
            store.apply(rows, emptyList(), account.copy(acceptedVersion = 0))
        }
        return sync()
    }

    // ---- devices, revocation, rotation -------------------------------------------------------

    /**
     * Re-reads the device list: devices certified by a pinned device are pinned; self-enrolled
     * ones are listed untrusted until the user confirms them; revoked ones are marked.
     */
    @Suppress("NestedBlockDepth") // Fixpoint over certificate chains.
    private suspend fun refreshDevices(
        account: AccountState,
        api: UotpApi = api(account),
    ): AccountState {
        val list = api.devices(signer(account))
        val pinned = account.pinned.associateBy { it.deviceId }.toMutableMap()
        var changed = true
        while (changed) {
            changed = false
            for (d in list.devices) {
                val known = pinned[d.deviceId]
                val revoked = d.revokedAt != null
                if (known != null) {
                    if (revoked && !known.revoked) {
                        pinned[d.deviceId] = known.copy(revoked = true)
                        changed = true
                    }
                    continue
                }
                val voucher = d.addedBy?.let { account.copy(pinned = pinned.values.toList()).pinnedKey(it) }
                val vouched =
                    voucher != null &&
                        Ed25519.verifyB64u(
                            voucher,
                            Statements.device(account.accountId, d.deviceId, d.ed25519, d.x25519),
                            d.addedBySignature.orEmpty(),
                        )
                if (vouched || d.addedBy == null) {
                    pinned[d.deviceId] = PinnedDevice(d.deviceId, d.ed25519, d.label, trusted = vouched, revoked = revoked)
                    changed = true
                }
            }
        }
        val next = account.copy(pinned = pinned.values.toList(), devicesRevision = list.devicesRevision)
        store.apply(emptyList(), emptyList(), next)
        return next
    }

    /** The "Active sessions" list (decision 9). */
    suspend fun devices(): List<DeviceView> =
        mutex.withLock {
            val account = refreshDevices(requireAccount())
            account.pinned.map { DeviceView(it.deviceId, it.label, it.trusted, it.revoked, it.deviceId == account.deviceId) }
        }

    /** The user confirmed on this device that a self-enrolled device is theirs. */
    suspend fun trustDevice(deviceId: String) =
        mutex.withLock {
            val account = requireAccount()
            store.apply(
                emptyList(),
                emptyList(),
                account.copy(
                    pinned =
                        account.pinned.map {
                            if (it.deviceId ==
                                deviceId
                            ) {
                                it.copy(trusted = true)
                            } else {
                                it
                            }
                        },
                ),
            )
        }

    suspend fun revoke(deviceId: String) =
        mutex.withLock {
            val account = requireAccount()
            api(account).revoke(signer(account), deviceId)
            refreshDevices(account)
        }

    /**
     * After a revocation (crypto-format.md §8): new vault key for every remaining device, new
     * wraps (needs the password, or the recovery words in the paranoid setting).
     */
    suspend fun rotate(
        password: String?,
        recoveryWords: String?,
    ): SyncResult {
        val first = sync()
        if (first !is SyncResult.Synced) return first
        mutex.withLock {
            store.ensureWritable()
            val account = refreshDevices(requireAccount())
            val api = api(account)
            val keysNow = api.accountKeys(signer(account))
            val (kekPw, params, kekRk) = rotationKeks(keysNow, password, recoveryWords)
            val newEpoch = account.keyEpoch + 1
            val newVk = Sodium.random(VK_BYTES)
            val newCipher = VaultCipher(newVk, account.accountId, newEpoch)
            val oldCipher = store.cipher()
            val version = account.acceptedVersion + 1
            val live = store.rows().filter { it.serverLive }
            val upserts = live.associate { it.id to newCipher.seal(oldCipher.committed(it)!!, version) }
            val manifest = Statements.manifest(upserts.map { (id, blob) -> Statements.ManifestEntry(id.toString(), version, blob) })
            val keys = store.deviceKeys()
            val active = api.devices(signer(account)).devices.filter { it.revokedAt == null }
            val sealed =
                active.map { d ->
                    val box = SealedVaultKey.seal(newVk, newEpoch, account.accountId, B64u.decode(d.x25519))
                    DeviceKeyInput(
                        d.deviceId,
                        B64u.encode(box),
                        keys.signB64u(Statements.seal(account.accountId, newEpoch, d.deviceId, box)),
                    )
                }
            val bundle = VaultKeyWraps.bundle(newVk, newEpoch, kekRk, kekPw, params)
            val head = HeadInput(version, keys.signB64u(Statements.head(account.accountId, version, newEpoch, account.deviceId, manifest)))
            api.rotate(
                signer(account),
                RotateRequest(
                    account.acceptedVersion,
                    newEpoch,
                    head,
                    upserts.map { (id, b) ->
                        Upsert(id.toString(), B64u.encode(b))
                    },
                    emptyList(),
                    bundle.toDto(),
                    sealed,
                ),
            )
            val next = account.copy(acceptedVersion = version, keyEpoch = newEpoch, rotationRequired = false)
            store.installVaultKey(newVk, newEpoch, account.accountId, next)
            store.apply(
                live.map { it.copy(serverVersion = version, serverBlob = upserts.getValue(it.id), dirty = false, localBlob = null) },
                emptyList(),
                next,
            )
            newVk.wipe()
            kekRk.wipe()
            kekPw?.wipe()
        }
        return SyncResult.Synced(requireAccount().acceptedVersion, 0, 0)
    }

    /**
     * Checks [password] (or [recoveryWords]) against the account's wraps without changing anything,
     * so a step that needs them (rotation after "sign out everywhere else") fails before it starts.
     * @throws CryptoException.AuthenticationFailed when they are wrong.
     */
    suspend fun checkRotationSecret(
        password: String?,
        recoveryWords: String?,
    ) {
        val account = requireAccount()
        val keys = api(account).accountKeys(signer(account))
        val (kekPw, _, kekRk) =
            try {
                rotationKeks(keys, password, recoveryWords)
            } catch (e: IllegalArgumentException) {
                throw CryptoException.AuthenticationFailed("wrong recovery key", e)
            }
        kekPw?.wipe()
        kekRk.wipe()
    }

    private fun rotationKeks(
        keys: com.qtekfun.ultimateotp.core.sync.api.AccountKeys,
        password: String?,
        recoveryWords: String?,
    ): Triple<ByteArray?, KdfParams?, ByteArray> {
        val wrap = keys.passwordWrap
        val kdf = keys.passwordKdf
        if (password != null && wrap != null && kdf != null) {
            val params = KdfParams.decode(B64u.decode(kdf))
            val kek = PasswordKdf.derive(password, params)
            val opened = VaultKeyWraps.openWithKek(kek, wrap, params, keys.keyEpoch)
            opened.vaultKey.wipe()
            val kekRk = opened.recoveryKek ?: throw CryptoException.InvalidFormat("password wrap without recovery KEK")
            return Triple(kek, params, kekRk)
        }
        val words = requireNotNull(recoveryWords) { "rotation needs the password or the recovery key" }
        return Triple(null, null, VaultKeyWraps.recoveryKek(RecoveryKey.fromWords(words)))
    }

    /** Another device rotated: our sealed key for the new epoch must be signed by a pinned device. */
    private suspend fun adoptRotatedKey(
        account: AccountState,
        api: UotpApi,
    ): AccountState {
        val keys = api.accountKeys(signer(account))
        val sealed = keys.deviceKey ?: reject("no sealed key for the new epoch")
        var current = account
        if (current.pinnedKey(sealed.sealedBy) == null) current = refreshDevices(current, api)
        val sealer = current.pinnedKey(sealed.sealedBy) ?: reject("new key sealed by an untrusted device")
        val box = B64u.decode(sealed.sealedVaultKey)
        if (!Ed25519.verifyB64u(sealer, Statements.seal(account.accountId, sealed.keyEpoch, account.deviceId, box), sealed.sealSignature)) {
            reject("bad seal signature")
        }
        val vk = SealedVaultKey.open(store.deviceKeys(), box, sealed.keyEpoch, account.accountId)
        val next = current.copy(keyEpoch = sealed.keyEpoch, keysRevision = keys.keysRevision)
        // Committed rows of the old epoch are replaced by the pull that follows (the rotation
        // rewrote every live item); pending ones are re-encrypted here.
        store.installVaultKey(vk, sealed.keyEpoch, account.accountId, next)
        vk.wipe()
        return next
    }

    // ---- helpers ------------------------------------------------------------------------------

    private fun reject(reason: String): Nothing = throw HeadRejectedException(reason)

    private suspend fun requireAccount(): AccountState = store.account() ?: error("no account")

    private fun api(account: AccountState): UotpApi = apiFor(account.serverUrl).also { it.clockOffset = account.clockOffset }

    private fun com.qtekfun.ultimateotp.core.crypto.KeyBundle.toDto() = KeyBundleDto(passwordWrap, passwordKdf, recoveryWrap)

    private companion object {
        const val FIRST_EPOCH = 1L
        const val MAX_COMMIT_ATTEMPTS = 3
        const val POLL_MS = 2_000L
        const val VK_BYTES = 32
        const val KEY_BYTES = 32
        const val SRP_PRIVATE_BYTES = 64
    }
}
