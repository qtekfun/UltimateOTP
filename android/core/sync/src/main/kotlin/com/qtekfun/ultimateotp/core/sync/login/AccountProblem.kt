// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.login

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import java.io.IOException

/**
 * Why a sign-up or login step failed, as the screens explain it. Built from the contract's
 * problem `code` (contracts/openapi.yaml, `Problem`), never from titles or details.
 */
sealed interface AccountProblem {
    /** `403 signup_disabled`: the server only takes accounts made with its CLI. */
    data object SignupDisabled : AccountProblem

    /** `409 email_taken`: the address already has an account; log in instead. */
    data object EmailTaken : AccountProblem

    /** `401 invalid_email_code`: wrong, used or expired code; retry or ask for a new one. */
    data object InvalidCode : AccountProblem

    /** The SRP proof failed (`srp_failed`). */
    data object WrongPassword : AccountProblem

    /** `429 account_locked`: too many wrong passwords; [retryAfterSeconds] from the problem. */
    data class AccountLocked(
        val retryAfterSeconds: Long?,
    ) : AccountProblem

    /** `429 rate_limited`. */
    data class RateLimited(
        val retryAfterSeconds: Long?,
    ) : AccountProblem

    /** `403 enrollment_network_denied`: the route is LAN-only on this server. */
    data object LanOnly : AccountProblem

    /** No answer from the server (no network, wrong URL, timeout): retry. */
    data object Network : AccountProblem

    /** Any other problem code. */
    data class Server(
        val code: String,
    ) : AccountProblem

    companion object {
        /** The problem behind [error], or null for errors that are bugs, not answers. */
        fun of(error: Throwable): AccountProblem? =
            when (error) {
                is ApiException -> fromCode(error.code, error.problem.retryAfter)
                is CryptoException.AuthenticationFailed -> WrongPassword
                is IOException -> Network
                else -> null
            }

        private fun fromCode(
            code: String,
            retryAfter: Long?,
        ): AccountProblem =
            when (code) {
                "signup_disabled" -> SignupDisabled

                "email_taken" -> EmailTaken

                "invalid_email_code" -> InvalidCode

                "srp_failed" -> WrongPassword

                "account_locked" -> AccountLocked(retryAfter)

                // Contract 1.2.0 `client_blocked`: also "wait", with the block's Retry-After.
                "rate_limited", "client_blocked" -> RateLimited(retryAfter)

                "enrollment_network_denied" -> LanOnly

                else -> Server(code)
            }
    }
}
