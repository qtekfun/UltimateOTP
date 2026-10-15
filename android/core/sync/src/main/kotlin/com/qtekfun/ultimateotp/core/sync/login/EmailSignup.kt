// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.login

import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Account creation from the app, like Ente Auth (contract 1.1.0, `POST /otp/v1/signup`, open
 * only with `UOTP_SIGNUP=enabled`):
 * 1. [requestCode]: `POST /otp/v1/login/email-code` emails a 6-digit code to the new address;
 * 2. [prepare]: the password makes the account keys on the device, as the bootstrap does (vault
 *    key wraps, SRP record, a new 24-word recovery key);
 * 3. the user saves the recovery words and confirms it ([Draft.confirmRecoverySaved]);
 * 4. [create]: sends the code, the key bundle and this device's keys, then syncs, which uploads
 *    the entries already on the device as the initial vault.
 *
 * The server checks the code only in step 4: on `invalid_email_code` keep the [Draft] and ask for
 * the code again (or a new one); the password and the recovery words stay valid.
 */
class EmailSignup(
    private val engine: SyncEngine,
    private val apiFor: (String) -> UotpApi,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / MILLIS },
) {
    /** The keys of the account being created. Kept in memory only, never persisted. */
    class Draft internal constructor(
        internal val keys: SyncEngine.NewAccountKeys,
    ) {
        /** The 24-word recovery key: show it once (decision 10). */
        val recoveryWords: List<String> get() = keys.recoveryWords

        /** Set when the user said they saved [recoveryWords]; [create] refuses to run before. */
        var recoverySaved: Boolean = false
            private set

        fun confirmRecoverySaved() {
            recoverySaved = true
        }
    }

    /**
     * Emails a code to [email] (always `202`: the server sends one to a new address only when
     * sign-up is open). @return the earliest time (Unix seconds) to offer a new code.
     */
    suspend fun requestCode(
        server: String,
        email: String,
    ): Long {
        apiFor(server).requestEmailCode(normalize(email), forSignup = true)
        return nowSeconds() + RESEND_COOLDOWN_S
    }

    /** Makes the account keys for [password] (Argon2id, seconds): off the main thread. */
    suspend fun prepare(password: String): Draft {
        require(password.isNotEmpty()) { "a password is required" }
        return withContext(Dispatchers.Default) { Draft(engine.newAccountKeys(password)) }
    }

    /**
     * Creates the account and this device, then syncs once.
     * @return the first sync's result, or null when it could not reach the server (the account
     *   exists; live sync retries later).
     * @throws com.qtekfun.ultimateotp.core.sync.api.ApiException with the contract's codes
     *   (`signup_disabled`, `email_taken`, `invalid_email_code`, `rate_limited`, ...).
     */
    suspend fun create(
        server: String,
        email: String,
        code: String,
        draft: Draft,
        label: String,
    ): SyncResult? {
        check(draft.recoverySaved) { "confirm the recovery key first" }
        engine.signup(server, normalize(email), code.trim().ifBlank { null }, draft.keys, label)
        // The account exists now: whatever the first sync meets (no network, a store that wants
        // the user to authenticate) must not turn into a failed sign-up. Live sync retries.
        return try {
            engine.sync()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        const val RESEND_COOLDOWN_S = 60L
        private const val MILLIS = 1000L

        /** Account identifiers are compared in lower case (contract `Email`). */
        fun normalize(email: String): String = email.trim().lowercase()
    }
}
