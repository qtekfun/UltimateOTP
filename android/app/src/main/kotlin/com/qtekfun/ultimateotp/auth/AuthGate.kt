// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.auth

import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import com.qtekfun.ultimateotp.core.vault.secure.KeyInvalidatedException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/** What an operation run through [AuthGate.run] came to. */
sealed interface GateResult<out T> {
    data class Done<T>(
        val value: T,
    ) : GateResult<T>

    /** The user dismissed the prompt or it failed; nothing was changed. A [Notice] was posted. */
    data object Declined : GateResult<Nothing>

    /** The Keystore key is gone or unusable; retrying cannot help. A [Notice] was posted. */
    data object KeyLost : GateResult<Nothing>

    /** Only from [AuthGate.attempt]: any other failure, reported as a [Notice.Failed]. */
    data object Failed : GateResult<Nothing>
}

/** A message the root of the app shows once, whatever screen the operation came from. */
sealed interface Notice {
    data object Cancelled : Notice

    data object KeyLost : Notice

    /** [what]: the exception's class name only, never its message (it may carry secrets). */
    data class Failed(
        val what: String,
    ) : Notice
}

/**
 * The one place where an expired Keystore authentication becomes a prompt and a retry.
 *
 * The Keystore key behind the vault needs the user to have authenticated in the last 30 s, and
 * the app cannot know when that lapses. Operations that write secrets therefore run inside
 * [run]: if they throw [AuthenticationRequiredException] the gate publishes a [Prompt], the root
 * composable shows the BiometricPrompt / device credential flow and answers it, and the
 * operation is run again from its start. Operations must be safe to repeat up to the first
 * thing they change; the engine's preflight guarantees that for everything that talks to the
 * server.
 *
 * On cancel or failure [run] returns [GateResult.Declined] and posts a [Notice]; the caller puts
 * its screen back where it was. [KeyInvalidatedException] returns [GateResult.KeyLost]. Every
 * other exception propagates to the caller, which owns mapping it to its own failed state.
 */
@Singleton
class AuthGate
    @Inject
    constructor() {
        /** An authentication request; the root answers with [succeed] or [fail] exactly once. */
        class Prompt internal constructor(
            val id: Long,
            private val answer: CompletableDeferred<String?>,
        ) {
            fun succeed() {
                answer.complete(null)
            }

            fun fail(message: String) {
                answer.complete(message)
            }
        }

        private val _prompt = MutableStateFlow<Prompt?>(null)

        /** The request the root composable must show now, or null. */
        val prompt: StateFlow<Prompt?> = _prompt.asStateFlow()

        private val _notice = MutableStateFlow<Notice?>(null)

        /** A message to show until [noticeShown]. */
        val notice: StateFlow<Notice?> = _notice.asStateFlow()

        private val promptLock = Mutex()
        private var nextId = 0L

        @Volatile private var authentications = 0

        fun noticeShown() {
            _notice.value = null
        }

        /** For failures the caller maps itself but the person must still be told (generic text). */
        fun report(error: Throwable) {
            _notice.value = Notice.Failed(error.javaClass.simpleName)
        }

        /**
         * [run], for operations with no error mapping of their own (add, edit, import, ...): any
         * other exception is reported as a [Notice.Failed] instead of ending the process.
         */
        @Suppress("TooGenericExceptionCaught")
        suspend fun <T> attempt(block: suspend () -> T): GateResult<T> =
            try {
                run(block)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                report(e)
                GateResult.Failed
            }

        @Suppress("ReturnCount")
        suspend fun <T> run(block: suspend () -> T): GateResult<T> {
            repeat(MAX_ATTEMPTS) {
                val seen = authentications
                try {
                    return GateResult.Done(block())
                } catch (e: CancellationException) {
                    throw e
                } catch (_: KeyInvalidatedException) {
                    _notice.value = Notice.KeyLost
                    return GateResult.KeyLost
                } catch (_: AuthenticationRequiredException) {
                    if (!authenticate(seen)) {
                        _notice.value = Notice.Cancelled
                        return GateResult.Declined
                    }
                }
            }
            // Authenticated, and still refused: the window cannot be satisfied (clock, policy).
            _notice.value = Notice.Cancelled
            return GateResult.Declined
        }

        /**
         * One prompt at a time. A caller that waited for the lock while another one authenticated
         * does not ask again: it just retries.
         */
        private suspend fun authenticate(seen: Int): Boolean =
            promptLock.withLock {
                if (authentications != seen) return@withLock true
                val answer = CompletableDeferred<String?>()
                val prompt = Prompt(++nextId, answer)
                _prompt.value = prompt
                try {
                    val error = answer.await()
                    if (error == null) authentications++
                    error == null
                } finally {
                    _prompt.compareAndSet(prompt, null)
                }
            }

        private companion object {
            const val MAX_ATTEMPTS = 3
        }
    }
