// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.account

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.sync.api.RemovedCounts
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class AccountAction { DELETE_ACCOUNT, CHANGE_EMAIL, SIGN_OUT_OTHERS, EXPORT }

/** How an action ended. */
sealed interface AccountActionResult {
    data class AccountDeleted(
        val removed: RemovedCounts,
    ) : AccountActionResult

    data class EmailChanged(
        val email: String,
    ) : AccountActionResult

    data class SignedOutOthers(
        val revoked: Int,
        val rotated: Boolean,
    ) : AccountActionResult

    /** The server's export document, to be saved by the screen. */
    data class Exported(
        val json: String,
    ) : AccountActionResult {
        override fun toString(): String = "Exported(${json.length} chars)"
    }
}

/**
 * Where an account action is. Every screen step is a state, [problem] is why the last attempt
 * failed (the state stays where it was: a failure never moves the flow forward).
 */
sealed interface AccountActionState {
    data object Idle : AccountActionState

    /** The user has to confirm [action] (the warning is shown); nothing was sent yet. */
    data class Confirming(
        val action: AccountAction,
        val problem: AccountProblem? = null,
    ) : AccountActionState

    /** A code was emailed to the account's address for [action]; it is typed here. */
    data class AwaitingEmailCode(
        val action: AccountAction,
        val problem: AccountProblem? = null,
    ) : AccountActionState

    /** Email change started: the code went to [newEmail]. */
    data class AwaitingNewAddressCode(
        val newEmail: String,
        val problem: AccountProblem? = null,
    ) : AccountActionState

    data class Working(
        val action: AccountAction,
    ) : AccountActionState

    data class Done(
        val result: AccountActionResult,
    ) : AccountActionState
}

/**
 * The account-management screens' ViewModel logic, free of Android types: the steps (confirm,
 * prove, wait for the code), the error mapping (problem codes, never texts), and the guarantee
 * that a failure leaves server and local state as they were. An action sent out of order
 * (without its confirmation step) is a programming error and throws.
 */
class AccountActions(
    private val management: AccountManagement,
) {
    private val _state = MutableStateFlow<AccountActionState>(AccountActionState.Idle)
    val state: StateFlow<AccountActionState> = _state.asStateFlow()

    /** First step of every action: shows the confirmation. */
    fun begin(action: AccountAction) {
        check(_state.value is AccountActionState.Idle || _state.value is AccountActionState.Done) { "another action is in progress" }
        _state.value = AccountActionState.Confirming(action)
    }

    fun cancel() {
        if (_state.value !is AccountActionState.Working) _state.value = AccountActionState.Idle
    }

    /** For [AccountAction.DELETE_ACCOUNT] and [AccountAction.CHANGE_EMAIL]: email a code instead of typing the password. */
    suspend fun requestEmailCode() {
        val current = _state.value
        val action = current.actionOrNull()?.takeIf { it.needsProof() } ?: error("no action waiting for a proof")
        step(current, { _, problem -> AccountActionState.Confirming(action, problem) }) {
            management.requestEmailCode()
            AccountActionState.AwaitingEmailCode(action)
        }
    }

    suspend fun deleteAccount(proof: ReauthProof) {
        val current = requireProofStep(AccountAction.DELETE_ACCOUNT)
        run(current, AccountAction.DELETE_ACCOUNT) {
            AccountActionState.Done(AccountActionResult.AccountDeleted(management.deleteAccount(proof).removed))
        }
    }

    suspend fun changeEmail(
        newEmail: String,
        proof: ReauthProof,
        lang: String? = null,
    ) {
        require(newEmail.contains('@') && newEmail.length <= MAX_EMAIL) { "not an email address" }
        val current = requireProofStep(AccountAction.CHANGE_EMAIL)
        run(current, AccountAction.CHANGE_EMAIL) {
            management.requestEmailChange(newEmail, proof, lang)
            AccountActionState.AwaitingNewAddressCode(newEmail.trim().lowercase())
        }
    }

    suspend fun confirmEmailChange(code: String) {
        val current = _state.value as? AccountActionState.AwaitingNewAddressCode ?: error("no email change pending")
        step(current, { s, problem -> (s as AccountActionState.AwaitingNewAddressCode).copy(problem = problem) }) {
            AccountActionState.Done(AccountActionResult.EmailChanged(management.confirmEmailChange(code)))
        }
    }

    suspend fun signOutOthers(
        password: String? = null,
        recoveryWords: String? = null,
    ) {
        val current = _state.value as? AccountActionState.Confirming ?: error("not confirmed")
        check(current.action == AccountAction.SIGN_OUT_OTHERS) { "not confirmed" }
        run(current, AccountAction.SIGN_OUT_OTHERS) {
            val r = management.signOutOthers(password, recoveryWords)
            AccountActionState.Done(AccountActionResult.SignedOutOthers(r.revoked, r.rotated))
        }
    }

    suspend fun export() {
        val current = _state.value as? AccountActionState.Confirming ?: error("not confirmed")
        check(current.action == AccountAction.EXPORT) { "not confirmed" }
        run(current, AccountAction.EXPORT) { AccountActionState.Done(AccountActionResult.Exported(management.exportEverything())) }
    }

    // ---- plumbing ------------------------------------------------------------------------------

    private fun AccountAction.needsProof() = this == AccountAction.DELETE_ACCOUNT || this == AccountAction.CHANGE_EMAIL

    private fun AccountActionState.actionOrNull(): AccountAction? =
        when (this) {
            is AccountActionState.Confirming -> action
            is AccountActionState.AwaitingEmailCode -> action
            else -> null
        }

    private fun requireProofStep(action: AccountAction): AccountActionState {
        val current = _state.value
        check(current.actionOrNull() == action) { "not confirmed" }
        return current
    }

    private suspend fun run(
        current: AccountActionState,
        action: AccountAction,
        block: suspend () -> AccountActionState,
    ) {
        _state.value = AccountActionState.Working(action)
        step(current, { s, problem -> s.withProblem(problem) }, block)
    }

    private fun AccountActionState.withProblem(problem: AccountProblem): AccountActionState =
        when (this) {
            is AccountActionState.Confirming -> copy(problem = problem)
            is AccountActionState.AwaitingEmailCode -> copy(problem = problem)
            is AccountActionState.AwaitingNewAddressCode -> copy(problem = problem)
            else -> this
        }

    /** Runs [block]; on failure goes back to [current] (or what [onFailure] builds) with the problem. */
    private suspend fun step(
        current: AccountActionState,
        onFailure: (AccountActionState, AccountProblem) -> AccountActionState,
        block: suspend () -> AccountActionState,
    ) {
        _state.value =
            try {
                block()
            } catch (e: java.io.IOException) {
                onFailure(current, AccountProblem.of(e) ?: AccountProblem.Network)
            } catch (e: CryptoException) {
                onFailure(current, AccountProblem.of(e) ?: AccountProblem.WrongPassword)
            } catch (_: IllegalArgumentException) {
                // A recovery key that is not 24 valid words.
                onFailure(current, AccountProblem.WrongPassword)
            }
    }

    private companion object {
        const val MAX_EMAIL = 254
    }
}
