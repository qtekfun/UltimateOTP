// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
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
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.CalloutKind
import com.qtekfun.ultimateotp.ui.components.CopyWordsButton
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.PasswordField
import com.qtekfun.ultimateotp.ui.components.RecoveryWordsGrid
import com.qtekfun.ultimateotp.ui.components.StepHeader
import com.qtekfun.ultimateotp.ui.components.StrengthMeter
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import com.qtekfun.ultimateotp.ui.components.rememberWordsCopier
import com.qtekfun.ultimateotp.ui.theme.CodeStyles
import com.qtekfun.ultimateotp.ui.theme.Space
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
private const val STEPS = 4
private const val CODE_STEP = 2
private const val PASSWORD_STEP = 3

/** The 1-based position of [step] in the four-step sign-up; Working keeps the previous one. */
private fun position(step: SignupStep): Int? =
    when (step) {
        SignupStep.Email, is SignupStep.Failed -> 1
        is SignupStep.Code -> CODE_STEP
        SignupStep.Password -> PASSWORD_STEP
        is SignupStep.Recovery, SignupStep.Done -> STEPS
        is SignupStep.Working -> null
    }

@Composable
fun SignupScreen(
    defaultServer: String,
    label: String,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    model: SignupViewModel = hiltViewModel(),
) {
    val step by model.step.collectAsState()
    val words = rememberWordsCopier()
    LaunchedEffect(label) { model.deviceLabel = label }
    SignupContent(
        step = step,
        defaultServer = defaultServer,
        onBack = onBack,
        onLogin = onLogin,
        onSendCode = model::sendCode,
        onCode = model::enterCode,
        onResend = model::resend,
        onPassword = model::choosePassword,
        onRecoveryConfirmed = model::confirmRecoverySaved,
        onRetry = model::retry,
        onRestart = model::restart,
        onCopyWords = words,
    )
}

/** The sign-up screen, stateless: one layout for every step, with a progress bar. */
@Composable
fun SignupContent(
    step: SignupStep,
    defaultServer: String,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    onSendCode: (String, String) -> Unit,
    onCode: (String) -> Unit,
    onResend: () -> Unit,
    onPassword: (String) -> Unit,
    onRecoveryConfirmed: () -> Unit,
    onRetry: () -> Unit,
    onRestart: () -> Unit,
    onCopyWords: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var shown by rememberSaveable { mutableIntStateOf(1) }
    position(step)?.let { shown = it }
    FlowScaffold(
        title = stringResource(R.string.signup_title),
        onBack = onBack,
        modifier = modifier,
        step = shown,
        steps = STEPS,
    ) {
        when (step) {
            SignupStep.Email -> {
                SignupEmail(defaultServer, onSendCode, onLogin)
            }

            is SignupStep.Code -> {
                SignupCode(step, onCode, onResend)
            }

            SignupStep.Password -> {
                SignupPassword(onPassword)
            }

            is SignupStep.Recovery -> {
                SignupRecovery(step.words, onRecoveryConfirmed, onCopyWords)
            }

            is SignupStep.Working -> {
                Working(step.deriving)
            }

            SignupStep.Done -> {
                Done(stringResource(R.string.signup_done_title), stringResource(R.string.signup_done), onBack)
            }

            is SignupStep.Failed -> {
                SignupFailed(step, onRetry, onRestart, onLogin)
            }
        }
    }
}

/** A centred progress indicator with what is happening (the Argon2id derivation takes seconds). */
@Composable
internal fun Working(deriving: Boolean) {
    androidx.compose.foundation.layout.Column(
        Modifier.fillMaxWidth().padding(vertical = Space.Xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Space.Lg),
    ) {
        CircularProgressIndicator()
        Text(
            stringResource(if (deriving) R.string.deriving_hint else R.string.working),
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
        )
    }
}

/** The success state of a flow: a check, what happened, and the way out. */
@Composable
internal fun Done(
    title: String,
    body: String,
    onContinue: () -> Unit,
) {
    StepHeader(Icons.Filled.CheckCircle, title, body)
    Button(onClick = onContinue, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) { Text(stringResource(R.string.ok)) }
}

@Composable
private fun SignupEmail(
    defaultServer: String,
    onSend: (String, String) -> Unit,
    onLogin: () -> Unit,
) {
    var server by rememberSaveable { mutableStateOf(defaultServer) }
    var email by rememberSaveable { mutableStateOf("") }
    StepHeader(Icons.Filled.Email, stringResource(R.string.signup_email_title), stringResource(R.string.signup_intro))
    OutlinedTextField(
        server,
        { server = it },
        label = { Text(stringResource(R.string.server_url)) },
        singleLine = true,
        shape = MaterialTheme.shapes.medium,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        email,
        { email = it },
        label = { Text(stringResource(R.string.email)) },
        singleLine = true,
        shape = MaterialTheme.shapes.medium,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
        modifier = Modifier.fillMaxWidth(),
    )
    Button(
        enabled = server.isNotBlank() && '@' in email,
        onClick = { onSend(server, email) },
        modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
    ) { Text(stringResource(R.string.send_code)) }
    TextButton(onClick = onLogin, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.signup_have_account)) }
}

/** The 6-digit code field shared by sign-up and log in. */
@Composable
internal fun CodeField(
    code: String,
    onChange: (String) -> Unit,
    wrong: Boolean,
) {
    OutlinedTextField(
        code,
        { onChange(it.filter(Char::isDigit).take(CODE_LENGTH)) },
        label = { Text(stringResource(R.string.email_code)) },
        isError = wrong,
        singleLine = true,
        textStyle =
            CodeStyles.Medium.copy(
                textAlign = TextAlign.Center,
                letterSpacing =
                    androidx.compose.ui.unit
                        .TextUnit(6f, androidx.compose.ui.unit.TextUnitType.Sp),
            ),
        shape = MaterialTheme.shapes.medium,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
    if (wrong) {
        Text(
            stringResource(R.string.wrong_code),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

/** "Send a new code" with the cooldown in seconds. */
@Composable
internal fun ResendButton(
    resendAt: Long,
    onResend: () -> Unit,
) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / SECOND_MS) }
    LaunchedEffect(resendAt) {
        while (now < resendAt) {
            kotlinx.coroutines.delay(SECOND_MS)
            now = System.currentTimeMillis() / SECOND_MS
        }
    }
    val wait = resendAt - now
    TextButton(enabled = wait <= 0, onClick = onResend, modifier = Modifier.fillMaxWidth()) {
        Text(
            if (wait > 0) {
                androidx.compose.ui.res
                    .pluralStringResource(R.plurals.resend_in_seconds, wait.toInt(), wait.toInt())
            } else {
                stringResource(R.string.resend)
            },
        )
    }
}

@Composable
private fun SignupCode(
    step: SignupStep.Code,
    onCode: (String) -> Unit,
    onResend: () -> Unit,
) {
    var code by rememberSaveable(step.email, step.wrongCode) { mutableStateOf("") }
    StepHeader(Icons.Filled.MarkEmailRead, stringResource(R.string.code_step_title), stringResource(R.string.code_sent, step.email))
    CodeField(code, { code = it }, step.wrongCode)
    Button(enabled = code.length == CODE_LENGTH, onClick = { onCode(code) }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        Text(stringResource(R.string.next))
    }
    ResendButton(step.resendAt, onResend)
}

@Composable
private fun SignupPassword(onPassword: (String) -> Unit) {
    var password by rememberRetainedText("signup-password")
    var repeat by rememberRetainedText("signup-repeat")
    val strength = PasswordStrength.of(password)
    StepHeader(Icons.Filled.Lock, stringResource(R.string.password_step_title), stringResource(R.string.signup_password_warning))
    PasswordField(
        value = password,
        onValueChange = { password = it },
        label = stringResource(R.string.password),
        modifier = Modifier.fillMaxWidth(),
    )
    if (password.isNotEmpty()) StrengthMeter(strength)
    PasswordField(
        value = repeat,
        onValueChange = { repeat = it },
        label = stringResource(R.string.password_repeat),
        isError = repeat.isNotEmpty() && repeat != password,
        modifier = Modifier.fillMaxWidth(),
    )
    if (repeat.isNotEmpty() && repeat != password) {
        Text(
            stringResource(R.string.password_mismatch),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    Text(
        stringResource(R.string.deriving_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Button(
        enabled = strength.acceptable && repeat == password,
        onClick = { onPassword(password) },
        modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
    ) { Text(stringResource(R.string.next)) }
}

/** The recovery key, shown once (decision 10); the account is created only after the checkbox. */
@Composable
private fun SignupRecovery(
    words: List<String>,
    onConfirmed: () -> Unit,
    onCopy: (String) -> Unit,
) {
    var saved by rememberSaveable { mutableStateOf(false) }
    StepHeader(Icons.Filled.Key, stringResource(R.string.recovery_title))
    Callout(stringResource(R.string.recovery_body), kind = CalloutKind.WARNING)
    RecoveryWordsGrid(words)
    CopyWordsButton(words, onCopy, Modifier.fillMaxWidth())
    Row(
        Modifier
            .fillMaxWidth()
            .toggleable(value = saved, role = Role.Checkbox, onValueChange = { saved = it })
            .padding(vertical = Space.Xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.Sm),
    ) {
        Checkbox(saved, onCheckedChange = null)
        Text(stringResource(R.string.signup_recovery_confirm), style = MaterialTheme.typography.bodyMedium)
    }
    Button(enabled = saved, onClick = onConfirmed, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        Text(stringResource(R.string.signup_create))
    }
}

@Composable
private fun SignupFailed(
    step: SignupStep.Failed,
    onRetry: () -> Unit,
    onRestart: () -> Unit,
    onLogin: () -> Unit,
) {
    Callout(accountProblemText(step.problem), kind = CalloutKind.ERROR)
    when {
        step.problem == AccountProblem.SignupDisabled || step.problem == AccountProblem.EmailTaken -> {
            Button(onClick = onLogin, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.login_title)) }
            OutlinedButton(onClick = onRestart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.signup_other_server)) }
        }

        step.canRetry -> {
            Button(onClick = onRetry, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.try_again)) }
            OutlinedButton(onClick = onRestart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.signup_start_over)) }
        }

        else -> {
            Button(onClick = onRestart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.signup_start_over)) }
        }
    }
}
