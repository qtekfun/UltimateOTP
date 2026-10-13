// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.login.EmailLogin
import com.qtekfun.ultimateotp.sync.SyncController
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
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

    data class Failed(
        val unavailable: Boolean,
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
                    onWrong?.takeIf { e.status in WRONG_STATUSES }?.invoke() ?: LoginStep.Failed(unavailable = false)
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
            LoginStep.Code(ticket, resendAt)
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
private const val SECOND_MS = 1_000L

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(
    defaultServer: String,
    label: String,
    onBack: () -> Unit,
    model: LoginViewModel = hiltViewModel(),
) {
    val step by model.step.collectAsState()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.login_title)) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                    ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            when (val s = step) {
                is LoginStep.Email -> {
                    if (s.wrongPassword) Text(stringResource(R.string.wrong_password_again), color = MaterialTheme.colorScheme.error)
                    EmailStep(defaultServer, model::sendCode)
                }

                is LoginStep.Code -> {
                    CodeStep(s, onVerify = { model.verify(s, it) }, onResend = { model.resend(s) })
                }

                is LoginStep.Password -> {
                    PasswordStep(s) { model.complete(s, it, label) }
                }

                LoginStep.Working -> {
                    Text(stringResource(R.string.working))
                }

                LoginStep.Done -> {
                    Text(stringResource(R.string.login_done))
                    Button(onClick = onBack) { Text(stringResource(R.string.ok)) }
                }

                is LoginStep.Failed -> {
                    Text(
                        stringResource(if (s.unavailable) R.string.login_unavailable else R.string.login_failed),
                        color = MaterialTheme.colorScheme.error,
                    )
                    Button(onClick = model::restart) { Text(stringResource(R.string.try_again)) }
                }
            }
        }
    }
}

@Composable
private fun EmailStep(
    defaultServer: String,
    onSend: (String, String) -> Unit,
) {
    var server by remember { mutableStateOf(defaultServer) }
    var email by remember { mutableStateOf("") }
    OutlinedTextField(server, { server = it }, label = { Text(stringResource(R.string.server_url)) }, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
        email,
        { email = it },
        label = { Text(stringResource(R.string.email)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
        modifier = Modifier.fillMaxWidth(),
    )
    Button(enabled = server.isNotBlank() && '@' in email, onClick = { onSend(server, email) }) { Text(stringResource(R.string.send_code)) }
}

@Composable
private fun CodeStep(
    step: LoginStep.Code,
    onVerify: (String) -> Unit,
    onResend: () -> Unit,
) {
    var code by remember { mutableStateOf("") }
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / SECOND_MS) }
    LaunchedEffect(step.resendAt) {
        while (now < step.resendAt) {
            delay(SECOND_MS)
            now = System.currentTimeMillis() / SECOND_MS
        }
    }
    Text(stringResource(R.string.code_sent, step.ticket.email))
    OutlinedTextField(
        code,
        { code = it.filter(Char::isDigit).take(CODE_LENGTH) },
        label = { Text(stringResource(R.string.email_code)) },
        isError = step.wrongCode,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
    if (step.wrongCode) Text(stringResource(R.string.wrong_code), color = MaterialTheme.colorScheme.error)
    Button(enabled = code.length == CODE_LENGTH, onClick = { onVerify(code) }) { Text(stringResource(R.string.verify)) }
    val wait = step.resendAt - now
    TextButton(enabled = wait <= 0, onClick = onResend) {
        Text(if (wait > 0) stringResource(R.string.resend_in, wait) else stringResource(R.string.resend))
    }
}

@Composable
private fun PasswordStep(
    step: LoginStep.Password,
    onPassword: (String) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    OutlinedTextField(
        password,
        { password = it },
        label = { Text(stringResource(R.string.password)) },
        isError = step.wrongPassword,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
    )
    if (step.wrongPassword) Text(stringResource(R.string.wrong_password), color = MaterialTheme.colorScheme.error)
    Text(stringResource(R.string.deriving_hint))
    Button(enabled = password.isNotEmpty(), onClick = { onPassword(password) }) { Text(stringResource(R.string.sign_in)) }
}
