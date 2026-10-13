// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.auth.GateResult
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.sync.AccountRefresh
import com.qtekfun.ultimateotp.ui.components.CopyWordsButton
import com.qtekfun.ultimateotp.ui.components.PasswordField
import com.qtekfun.ultimateotp.util.PasswordStrength
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.IOException
import javax.inject.Inject

/** The sign-up steps, like Ente Auth's: email, emailed code, password, recovery key, done. */
sealed interface SignupStep {
    data object Email : SignupStep

    /** [wrongCode]: the server refused the code; the password and recovery key are kept. */
    data class Code(
        val email: String,
        val resendAt: Long,
        val wrongCode: Boolean = false,
    ) : SignupStep

    data object Password : SignupStep

    /** The 24 words, shown once; the account is created only after the user confirms. */
    data class Recovery(
        val words: List<String>,
    ) : SignupStep

    data class Working(
        val deriving: Boolean = false,
    ) : SignupStep

    data object Done : SignupStep

    /** [canRetry]: the same action may simply be repeated (network, rate limit, server error). */
    data class Failed(
        val problem: AccountProblem,
        val canRetry: Boolean,
    ) : SignupStep
}

@HiltViewModel
class SignupViewModel
    @Inject
    constructor(
        private val signup: EmailSignup,
        private val refresh: AccountRefresh,
        private val gate: AuthGate,
    ) : ViewModel() {
        private val _step = MutableStateFlow<SignupStep>(SignupStep.Email)
        val step: StateFlow<SignupStep> = _step.asStateFlow()

        private var server = ""
        private var email = ""
        private var code = ""
        private var resendAt = 0L
        private var draft: EmailSignup.Draft? = null
        private var lastAction: (() -> Unit)? = null

        /** Step 1: server and email; asks the server to email a code. */
        fun sendCode(
            server: String,
            email: String,
        ) {
            this.server = server.trim()
            this.email = EmailSignup.normalize(email)
            go(block = ::requestCode)
        }

        fun resend() = go(block = ::requestCode)

        private suspend fun requestCode(): SignupStep {
            resendAt = signup.requestCode(server, email)
            return SignupStep.Code(email, resendAt)
        }

        /** Step 2: the code is checked by the server at creation; with keys ready, create now. */
        fun enterCode(code: String) {
            this.code = code.trim()
            if (draft?.recoverySaved == true) create() else _step.value = SignupStep.Password
        }

        /** Step 3: the password makes the account keys (Argon2id, seconds). */
        fun choosePassword(password: String) {
            if (!PasswordStrength.of(password).acceptable) return
            go(deriving = true) {
                val made = signup.prepare(password)
                draft = made
                SignupStep.Recovery(made.recoveryWords)
            }
        }

        /** Step 4: the user saved the 24 words; creates the account and starts sync. */
        fun confirmRecoverySaved() {
            draft?.confirmRecoverySaved() ?: return
            create()
        }

        private fun create() =
            go {
                val keys = requireNotNull(draft)
                // The engine checks the Keystore before it sends /signup, so declining the prompt
                // leaves no account behind: back to the words, with the draft kept.
                when (gate.run { signup.create(server, email, code, keys, deviceLabel) }) {
                    is GateResult.Done -> {
                        draft = null
                        refresh.accountChanged()
                        SignupStep.Done
                    }

                    else -> {
                        SignupStep.Recovery(keys.recoveryWords)
                    }
                }
            }

        fun retry() {
            lastAction?.invoke()
        }

        /** Back to the email step; a draft whose words were not confirmed is dropped. */
        fun restart() {
            if (draft?.recoverySaved != true) draft = null
            _step.value = SignupStep.Email
        }

        /** Set by the screen: the label sent to the server (decision 9). */
        var deviceLabel: String = "Android"

        private fun go(
            deriving: Boolean = false,
            block: suspend () -> SignupStep,
        ) {
            val action = { go(deriving, block) }
            lastAction = action
            viewModelScope.launch {
                _step.value = SignupStep.Working(deriving)
                _step.value =
                    try {
                        block()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: IOException) {
                        // ApiException (a problem document) or no answer at all.
                        failed(AccountProblem.of(e) ?: AccountProblem.Network)
                    } catch (_: Exception) {
                        // A bug or a full disk: a failed step the person can retry, never a dead app.
                        failed(AccountProblem.Unexpected)
                    }
            }
        }

        private fun failed(problem: AccountProblem): SignupStep =
            when (problem) {
                AccountProblem.InvalidCode -> SignupStep.Code(email, resendAt, wrongCode = true)
                AccountProblem.SignupDisabled, AccountProblem.EmailTaken -> SignupStep.Failed(problem, canRetry = false)
                else -> SignupStep.Failed(problem, canRetry = true)
            }
    }

private const val CODE_LENGTH = 6
private const val SECOND_MS = 1_000L
private const val WORDS_PER_LINE = 3

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignupScreen(
    defaultServer: String,
    label: String,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    model: SignupViewModel = hiltViewModel(),
) {
    val step by model.step.collectAsState()
    LaunchedEffect(label) { model.deviceLabel = label }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.signup_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (val s = step) {
                SignupStep.Email -> {
                    SignupEmail(defaultServer, model::sendCode, onLogin)
                }

                is SignupStep.Code -> {
                    SignupCode(s, model::enterCode, model::resend)
                }

                SignupStep.Password -> {
                    SignupPassword(model::choosePassword)
                }

                is SignupStep.Recovery -> {
                    SignupRecovery(s.words, model::confirmRecoverySaved)
                }

                is SignupStep.Working -> {
                    Text(stringResource(if (s.deriving) R.string.deriving_hint else R.string.working))
                }

                SignupStep.Done -> {
                    Text(stringResource(R.string.signup_done))
                    Button(onClick = onBack) { Text(stringResource(R.string.ok)) }
                }

                is SignupStep.Failed -> {
                    SignupFailed(s, model, onLogin)
                }
            }
        }
    }
}

@Composable
private fun SignupEmail(
    defaultServer: String,
    onSend: (String, String) -> Unit,
    onLogin: () -> Unit,
) {
    var server by remember { mutableStateOf(defaultServer) }
    var email by remember { mutableStateOf("") }
    Text(stringResource(R.string.signup_intro))
    OutlinedTextField(server, { server = it }, label = { Text(stringResource(R.string.server_url)) }, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
        email,
        { email = it },
        label = { Text(stringResource(R.string.email)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
        modifier = Modifier.fillMaxWidth(),
    )
    Button(enabled = server.isNotBlank() && '@' in email, onClick = { onSend(server, email) }) { Text(stringResource(R.string.send_code)) }
    TextButton(onClick = onLogin) { Text(stringResource(R.string.signup_have_account)) }
}

@Composable
private fun SignupCode(
    step: SignupStep.Code,
    onCode: (String) -> Unit,
    onResend: () -> Unit,
) {
    var code by remember(step) { mutableStateOf("") }
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / SECOND_MS) }
    LaunchedEffect(step.resendAt) {
        while (now < step.resendAt) {
            delay(SECOND_MS)
            now = System.currentTimeMillis() / SECOND_MS
        }
    }
    Text(stringResource(R.string.code_sent, step.email))
    OutlinedTextField(
        code,
        { code = it.filter(Char::isDigit).take(CODE_LENGTH) },
        label = { Text(stringResource(R.string.email_code)) },
        isError = step.wrongCode,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
    if (step.wrongCode) Text(stringResource(R.string.wrong_code), color = MaterialTheme.colorScheme.error)
    Button(enabled = code.length == CODE_LENGTH, onClick = { onCode(code) }) { Text(stringResource(R.string.next)) }
    val wait = step.resendAt - now
    TextButton(enabled = wait <= 0, onClick = onResend) {
        Text(if (wait > 0) stringResource(R.string.resend_in, wait) else stringResource(R.string.resend))
    }
}

@Composable
private fun SignupPassword(onPassword: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val strength = PasswordStrength.of(password)
    Text(stringResource(R.string.signup_password_warning))
    PasswordField(
        value = password,
        onValueChange = { password = it },
        label = stringResource(R.string.password),
        modifier = Modifier.fillMaxWidth(),
    )
    if (password.isNotEmpty()) {
        Text(
            stringResource(strengthText(strength)),
            color = if (strength.acceptable) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
        )
    }
    PasswordField(
        value = repeat,
        onValueChange = { repeat = it },
        label = stringResource(R.string.password_repeat),
        isError = repeat.isNotEmpty() && repeat != password,
        modifier = Modifier.fillMaxWidth(),
    )
    if (repeat.isNotEmpty() && repeat != password) Text(stringResource(R.string.password_mismatch), color = MaterialTheme.colorScheme.error)
    Text(stringResource(R.string.deriving_hint), style = MaterialTheme.typography.bodySmall)
    Button(enabled = strength.acceptable && repeat == password, onClick = { onPassword(password) }) {
        Text(stringResource(R.string.next))
    }
}

private fun strengthText(strength: PasswordStrength): Int =
    when (strength) {
        PasswordStrength.TOO_SHORT -> R.string.strength_too_short
        PasswordStrength.WEAK -> R.string.strength_weak
        PasswordStrength.FAIR -> R.string.strength_fair
        PasswordStrength.STRONG -> R.string.strength_strong
    }

/** The recovery key, shown once (decision 10); the account is created only after the checkbox. */
@Composable
private fun SignupRecovery(
    words: List<String>,
    onConfirmed: () -> Unit,
) {
    var saved by remember { mutableStateOf(false) }
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.recovery_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.recovery_body))
            Text(
                words.chunked(WORDS_PER_LINE).withIndex().joinToString("\n") { (i, line) ->
                    line.withIndex().joinToString("  ") { (j, w) -> "${i * WORDS_PER_LINE + j + 1}. $w" }
                },
                fontFamily = FontFamily.Monospace,
            )
            CopyWordsButton(words)
        }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(saved, { saved = it })
        Text(stringResource(R.string.signup_recovery_confirm))
    }
    Button(enabled = saved, onClick = onConfirmed, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.signup_create)) }
}

@Composable
private fun SignupFailed(
    step: SignupStep.Failed,
    model: SignupViewModel,
    onLogin: () -> Unit,
) {
    Text(accountProblemText(step.problem), color = MaterialTheme.colorScheme.error)
    when {
        step.problem == AccountProblem.SignupDisabled || step.problem == AccountProblem.EmailTaken -> {
            Button(onClick = onLogin, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.login_title)) }
            OutlinedButton(onClick = model::restart, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.signup_other_server))
            }
        }

        step.canRetry -> {
            Button(onClick = model::retry, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.try_again)) }
            OutlinedButton(onClick = model::restart, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.signup_start_over))
            }
        }

        else -> {
            Button(onClick = model::restart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.signup_start_over)) }
        }
    }
}
