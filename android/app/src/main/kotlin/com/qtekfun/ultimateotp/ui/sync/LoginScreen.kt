// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.core.sync.login.EmailLogin
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.CalloutKind
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.PasswordField
import com.qtekfun.ultimateotp.ui.components.StepHeader
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.IOException
import javax.inject.Inject

/** The login steps of decision 13: email, emailed code, password. */
sealed interface LoginStep {
    /** [wrongPassword]: the previous attempt failed; the emailed code works once, so start again. */
    data class Email(
        val wrongPassword: Boolean = false,
    ) : LoginStep

    data class Code(
        val ticket: EmailLogin.Ticket,
        val resendAt: Long,
        val wrongCode: Boolean = false,
    ) : LoginStep

    data class Password(
        val ticket: EmailLogin.Ticket,
        val wrongPassword: Boolean = false,
    ) : LoginStep

    data object Working : LoginStep

    data object Done : LoginStep

    /** [problem]: what the server answered, e.g. `account_locked` with its `retry_after`. */
    data class Failed(
        val unavailable: Boolean,
        val problem: AccountProblem? = null,
    ) : LoginStep
}

@HiltViewModel
class LoginViewModel
    @Inject
    constructor(
        private val login: EmailLogin,
        private val controller: SyncController,
    ) : ViewModel() {
        private val _step = MutableStateFlow<LoginStep>(LoginStep.Email())
        val step: StateFlow<LoginStep> = _step.asStateFlow()

        private fun go(
            block: suspend () -> LoginStep,
            onWrong: (() -> LoginStep)? = null,
        ) = viewModelScope.launch {
            val previous = _step.value
            _step.value = LoginStep.Working
            _step.value =
                try {
                    block()
                } catch (_: UnsupportedOperationException) {
                    LoginStep.Failed(unavailable = true)
                } catch (e: ApiException) {
                    onWrong?.takeIf { e.status in WRONG_STATUSES }?.invoke() ?: LoginStep.Failed(false, AccountProblem.of(e))
                } catch (_: CryptoException) {
                    onWrong?.invoke() ?: previous
                } catch (_: IOException) {
                    LoginStep.Failed(unavailable = false)
                }
        }

        fun sendCode(
            server: String,
            email: String,
        ) = go({
            val (ticket, resendAt) = login.requestCode(server.trim(), email.trim().lowercase())
            if (ticket.codeRequired) LoginStep.Code(ticket, resendAt) else LoginStep.Password(login.verifyCode(ticket, ""))
        })

        fun resend(step: LoginStep.Code) = sendCode(step.ticket.server, step.ticket.email)

        fun verify(
            step: LoginStep.Code,
            code: String,
        ) = go({ LoginStep.Password(login.verifyCode(step.ticket, code.trim())) }) {
            step.copy(wrongCode = true)
        }

        fun complete(
            step: LoginStep.Password,
            password: String,
            label: String,
        ) = go({
            login.complete(step.ticket, password, label)
            controller.refresh()
            LoginStep.Done
        }) { LoginStep.Email(wrongPassword = true) }

        fun restart() {
            _step.value = LoginStep.Email()
        }

        private companion object {
            val WRONG_STATUSES = setOf(400, 401, 403)
        }
    }

private const val CODE_LENGTH = 6
private const val STEPS = 3

private fun position(step: LoginStep): Int? =
    when (step) {
        is LoginStep.Email, is LoginStep.Failed -> 1
        is LoginStep.Code -> 2
        is LoginStep.Password, LoginStep.Done -> STEPS
        LoginStep.Working -> null
    }

@Composable
fun LoginScreen(
    defaultServer: String,
    label: String,
    onBack: () -> Unit,
    model: LoginViewModel = hiltViewModel(),
) {
    val step by model.step.collectAsState()
    LoginContent(
        step = step,
        defaultServer = defaultServer,
        onBack = onBack,
        onSendCode = model::sendCode,
        onVerify = { s, code -> model.verify(s, code) },
        onResend = { model.resend(it) },
        onPassword = { s, password -> model.complete(s, password, label) },
        onRestart = model::restart,
    )
}

/** The log-in screen, stateless: email, emailed code, password, with a progress bar. */
@Composable
fun LoginContent(
    step: LoginStep,
    defaultServer: String,
    onBack: () -> Unit,
    onSendCode: (String, String) -> Unit,
    onVerify: (LoginStep.Code, String) -> Unit,
    onResend: (LoginStep.Code) -> Unit,
    onPassword: (LoginStep.Password, String) -> Unit,
    onRestart: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var shown by rememberSaveable { androidx.compose.runtime.mutableIntStateOf(1) }
    position(step)?.let { shown = it }
    FlowScaffold(title = stringResource(R.string.login_title), onBack = onBack, modifier = modifier, step = shown, steps = STEPS) {
        when (step) {
            is LoginStep.Email -> {
                if (step.wrongPassword) Callout(stringResource(R.string.wrong_password_again), kind = CalloutKind.ERROR)
                EmailStep(defaultServer, onSendCode)
            }

            is LoginStep.Code -> {
                CodeStep(step, onVerify = { onVerify(step, it) }, onResend = { onResend(step) })
            }

            is LoginStep.Password -> {
                PasswordStep(step) { onPassword(step, it) }
            }

            LoginStep.Working -> {
                Working(deriving = false)
            }

            LoginStep.Done -> {
                Done(stringResource(R.string.login_done_title), stringResource(R.string.login_done), onBack)
            }

            is LoginStep.Failed -> {
                Callout(
                    when {
                        step.unavailable -> {
                            stringResource(R.string.login_unavailable)
                        }

                        step.problem is AccountProblem.AccountLocked || step.problem is AccountProblem.RateLimited -> {
                            accountProblemText(step.problem)
                        }

                        else -> {
                            stringResource(R.string.login_failed)
                        }
                    },
                    kind = CalloutKind.ERROR,
                )
                Button(onClick = onRestart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.try_again)) }
            }
        }
    }
}

@Composable
private fun EmailStep(
    defaultServer: String,
    onSend: (String, String) -> Unit,
) {
    var server by rememberSaveable { mutableStateOf(defaultServer) }
    var email by rememberSaveable { mutableStateOf("") }
    StepHeader(Icons.Filled.Email, stringResource(R.string.login_email_title), stringResource(R.string.login_intro))
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
}

@Composable
private fun CodeStep(
    step: LoginStep.Code,
    onVerify: (String) -> Unit,
    onResend: () -> Unit,
) {
    var code by rememberSaveable(step.wrongCode) { mutableStateOf("") }
    StepHeader(Icons.Filled.MarkEmailRead, stringResource(R.string.code_step_title), stringResource(R.string.code_sent, step.ticket.email))
    CodeField(code, { code = it }, step.wrongCode)
    Button(enabled = code.length == CODE_LENGTH, onClick = { onVerify(code) }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        Text(stringResource(R.string.verify))
    }
    ResendButton(step.resendAt, onResend)
}

@Composable
private fun PasswordStep(
    step: LoginStep.Password,
    onPassword: (String) -> Unit,
) {
    var password by rememberRetainedText("login-password")
    StepHeader(Icons.Filled.Lock, stringResource(R.string.login_password_title), stringResource(R.string.deriving_hint))
    PasswordField(
        value = password,
        onValueChange = { password = it },
        label = stringResource(R.string.password),
        isError = step.wrongPassword,
        modifier = Modifier.fillMaxWidth(),
    )
    if (step.wrongPassword) {
        Text(
            stringResource(R.string.wrong_password),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    Button(enabled = password.isNotEmpty(), onClick = { onPassword(password) }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        Text(stringResource(R.string.sign_in))
    }
}
