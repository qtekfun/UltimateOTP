// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.account

import com.qtekfun.ultimateotp.core.crypto.B64u
import com.qtekfun.ultimateotp.core.crypto.KdfParams
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.crypto.Srp
import com.qtekfun.ultimateotp.core.crypto.wipe
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.core.sync.SyncStore
import com.qtekfun.ultimateotp.core.sync.api.AccountDeleted
import com.qtekfun.ultimateotp.core.sync.api.ChangeEmailRequest
import com.qtekfun.ultimateotp.core.sync.api.ConfirmEmailRequest
import com.qtekfun.ultimateotp.core.sync.api.DeleteAccountRequest
import com.qtekfun.ultimateotp.core.sync.api.EmailChangePending
import com.qtekfun.ultimateotp.core.sync.api.Reauth
import com.qtekfun.ultimateotp.core.sync.api.ReauthSrpProof
import com.qtekfun.ultimateotp.core.sync.api.ReauthSrpRequest
import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** How the user proves who they are for a dangerous action (contract 1.2.0 `Reauth`). */
sealed interface ReauthProof {
    /** The 6-digit code emailed by [AccountManagement.requestEmailCode]. */
    data class EmailCode(
        val code: String,
    ) : ReauthProof

    /** The account password, proven with SRP (the password itself is never sent). */
    class Password(
        val password: String,
    ) : ReauthProof {
        override fun toString(): String = "Password(<redacted>)"
    }
}

/** What "sign out everywhere else" did. */
data class SignedOutOthers(
    val revoked: Int,
    /** True when the vault key was rotated right after (needed so the signed-out devices cannot read new data). */
    val rotated: Boolean,
)

/**
 * The account routes of contract 1.2.0 on top of the signed device: delete the account, change
 * the email, sign out every other device, export everything. Every dangerous action needs a
 * fresh proof; local state changes only after the server said yes.
 */
class AccountManagement(
    private val store: SyncStore,
    private val engine: SyncEngine,
    private val apiFor: (String) -> UotpApi,
) {
    private suspend fun account(): AccountState = store.account() ?: error("no account")

    private fun api(account: AccountState): UotpApi = apiFor(account.serverUrl).also { it.clockOffset = account.clockOffset }

    private fun signer(account: AccountState) = Signer(store.deviceKeys(), account.deviceId)

    /** Emails a fresh code to the account's own address (the alternative to proving the password). */
    suspend fun requestEmailCode() {
        val account = account()
        api(account).reauthEmailCode(signer(account))
    }

    /**
     * Deletes the account and its server data for good. On success the device forgets the account
     * and keeps its entries as a local, offline vault.
     */
    suspend fun deleteAccount(proof: ReauthProof): AccountDeleted {
        val account = account()
        val result = api(account).deleteAccount(signer(account), DeleteAccountRequest(reauth(account, proof)))
        store.leaveAccount()
        return result
    }

    /** Starts the change: a code goes to [newEmail]; [confirmEmailChange] finishes it. */
    suspend fun requestEmailChange(
        newEmail: String,
        proof: ReauthProof,
        lang: String? = null,
    ): EmailChangePending {
        val account = account()
        val reauth = reauth(account, proof)
        return api(account).requestEmailChange(signer(account), ChangeEmailRequest(newEmail.trim().lowercase(), lang, reauth))
    }

    /** @return the account's new address. */
    suspend fun confirmEmailChange(code: String): String {
        val account = account()
        return api(account).confirmEmailChange(signer(account), ConfirmEmailRequest(code.trim())).email
    }

    /**
     * Revokes every other device, then rotates the vault key so they cannot read anything new.
     * Rotation needs [password] or [recoveryWords]; they are checked before anything is revoked,
     * and without either the devices are still signed out and [SignedOutOthers.rotated] is false.
     */
    suspend fun signOutOthers(
        password: String? = null,
        recoveryWords: String? = null,
    ): SignedOutOthers {
        val canRotate = password != null || recoveryWords != null
        if (canRotate) withContext(Dispatchers.Default) { engine.checkRotationSecret(password, recoveryWords) }
        val account = account()
        val result = api(account).revokeOthers(signer(account))
        var rotated = false
        if (canRotate && result.revoked.isNotEmpty()) {
            val outcome = withContext(Dispatchers.Default) { engine.rotate(password, recoveryWords) }
            rotated = outcome is SyncResult.Synced
        }
        return SignedOutOthers(result.revoked.size, rotated)
    }

    /** Everything the server holds for the account, as one JSON document (ciphertext and public keys only). */
    suspend fun exportEverything(): String {
        val account = account()
        return api(account).exportAccount(signer(account))
    }

    private suspend fun reauth(
        account: AccountState,
        proof: ReauthProof,
    ): Reauth =
        when (proof) {
            is ReauthProof.EmailCode -> Reauth(emailCode = proof.code.trim())
            is ReauthProof.Password -> Reauth(srp = srpProof(account, proof.password))
        }

    private suspend fun srpProof(
        account: AccountState,
        password: String,
    ): ReauthSrpProof {
        val api = api(account)
        val privateA = Sodium.random(SRP_PRIVATE_BYTES)
        // `A` depends only on the private value: the handshake's identity and salt come with `B`.
        val publicA = Srp.start(ByteArray(KEY_BYTES), "", ByteArray(0), privateA = privateA).publicA
        val session = api.reauthSrp(signer(account), ReauthSrpRequest(B64u.encode(publicA)))
        return withContext(Dispatchers.Default) {
            val params = KdfParams.decode(B64u.decode(session.passwordKdf)).checkReaderLimits()
            val kek = PasswordKdf.derive(password, params)
            try {
                val srp = Srp.start(kek, session.srpUserId, B64u.decode(session.srpSalt), privateA = privateA)
                ReauthSrpProof(session.sessionId, B64u.encode(srp.proof(B64u.decode(session.srpB))))
            } finally {
                kek.wipe()
                privateA.wipe()
            }
        }
    }

    private companion object {
        const val SRP_PRIVATE_BYTES = 64
        const val KEY_BYTES = 32
    }
}
