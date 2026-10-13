// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.account.AccountAction
import com.qtekfun.ultimateotp.core.sync.account.AccountActionResult
import com.qtekfun.ultimateotp.core.sync.account.AccountActionState
import com.qtekfun.ultimateotp.core.sync.account.AccountActions
import com.qtekfun.ultimateotp.core.sync.account.AccountManagement
import com.qtekfun.ultimateotp.core.sync.account.ReauthProof
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.CalloutKind
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.PasswordField
import com.qtekfun.ultimateotp.ui.components.RowDivider
import com.qtekfun.ultimateotp.ui.components.SettingsGroup
import com.qtekfun.ultimateotp.ui.components.SettingsRow
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/** The state machine is in :core:sync ([AccountActions]); this only hands it to the screen. */
@HiltViewModel
class AccountViewModel
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        management: AccountManagement,
        private val vault: VaultRepository,
    ) : ViewModel() {
        private val actions = AccountActions(management)
        val state: StateFlow<AccountActionState> = actions.state
        val signedIn = MutableStateFlow(false)

        init {
            viewModelScope.launch { signedIn.value = vault.account() != null }
        }

        fun begin(action: AccountAction) = actions.begin(action)

        fun cancel() = actions.cancel()

        fun sendCode() = viewModelScope.launch { actions.requestEmailCode() }

        fun delete(proof: ReauthProof) = viewModelScope.launch { actions.deleteAccount(proof) }

        fun changeEmail(
            newEmail: String,
            proof: ReauthProof,
        ) = viewModelScope.launch { actions.changeEmail(newEmail, proof) }

        fun confirmEmail(code: String) = viewModelScope.launch { actions.confirmEmailChange(code) }

        fun signOutOthers(password: String) = viewModelScope.launch { actions.signOutOthers(password.ifBlank { null }) }

        fun export() = viewModelScope.launch { actions.export() }

        /** Writes the server's export document to [target]. */
        fun save(target: Uri) =
            viewModelScope.launch {
                val json = ((state.value as? AccountActionState.Done)?.result as? AccountActionResult.Exported)?.json ?: return@launch
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(target, "wt")?.use { it.write(json.toByteArray()) } }
            }
    }

@Composable
fun AccountScreen(
    onBack: () -> Unit,
    model: AccountViewModel = hiltViewModel(),
) {
    val state by model.state.collectAsState()
    val signedIn by model.signedIn.collectAsState()
    val saveTarget =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri -> uri?.let(model::save) }
    FlowScaffold(title = stringResource(R.string.account_settings), onBack = onBack) {
        if (!signedIn) {
            Callout(stringResource(R.string.account_no_account))
            return@FlowScaffold
        }
        when (val s = state) {
            AccountActionState.Idle -> {
                SettingsGroup(stringResource(R.string.account_settings)) {
                    ACTIONS.forEachIndexed { i, (action, label) ->
                        if (i > 0) RowDivider()
                        SettingsRow(
                            icon = actionIcon(action),
                            title = stringResource(label),
                            onClick = { model.begin(action) },
                            danger = action == AccountAction.DELETE_ACCOUNT,
                        )
                    }
                }
            }

            is AccountActionState.Confirming -> {
                ConfirmStep(s.action, s.problem, model)
            }

            is AccountActionState.AwaitingEmailCode -> {
                ConfirmStep(s.action, s.problem, model, codeSent = true)
            }

            is AccountActionState.AwaitingNewAddressCode -> {
                var code by rememberRetainedText("account-new-address-code")
                Text(s.newEmail, style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    code,
                    { code = it },
                    label = { Text(stringResource(R.string.account_email_code)) },
                    modifier = Modifier.fillMaxWidth(),
                )
                s.problem?.let { Callout(stringResource(R.string.account_problem, problemName(it)), kind = CalloutKind.ERROR) }
                Button(
                    onClick = { model.confirmEmail(code) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                    shape = MaterialTheme.shapes.large,
                ) { Text(stringResource(R.string.account_continue)) }
            }

            is AccountActionState.Working -> {
                Callout(stringResource(R.string.working))
            }

            is AccountActionState.Done -> {
                DoneText(s.result)
                if (s.result is AccountActionResult.Exported) {
                    LaunchedEffect(s) { saveTarget.launch("ultimateotp-server-export.json") }
                }
                FilledTonalButton(
                    onClick = model::cancel,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = MaterialTheme.shapes.large,
                ) { Text(stringResource(R.string.ok)) }
            }
        }
    }
}

private fun actionIcon(action: AccountAction): ImageVector =
    when (action) {
        AccountAction.CHANGE_EMAIL -> Icons.Filled.Email
        AccountAction.SIGN_OUT_OTHERS -> Icons.Filled.Devices
        AccountAction.EXPORT -> Icons.Filled.FileDownload
        AccountAction.DELETE_ACCOUNT -> Icons.Filled.DeleteForever
    }

private val ACTIONS =
    listOf(
        AccountAction.CHANGE_EMAIL to R.string.account_change_email,
        AccountAction.SIGN_OUT_OTHERS to R.string.account_sign_out_others,
        AccountAction.EXPORT to R.string.account_export,
        AccountAction.DELETE_ACCOUNT to R.string.account_delete,
    )

@Composable
private fun ConfirmStep(
    action: AccountAction,
    problem: AccountProblem?,
    model: AccountViewModel,
    codeSent: Boolean = false,
) {
    // Passwords and codes are kept across a fold or rotation but never saved to disk.
    var secret by rememberRetainedText("account-secret")
    var newEmail by rememberRetainedText("account-new-email")
    val warning =
        when (action) {
            AccountAction.DELETE_ACCOUNT -> R.string.account_confirm_delete
            AccountAction.SIGN_OUT_OTHERS -> R.string.account_confirm_others
            AccountAction.EXPORT -> R.string.account_confirm_export
            AccountAction.CHANGE_EMAIL -> R.string.account_confirm_email
        }
    Callout(
        stringResource(warning),
        kind = if (action == AccountAction.DELETE_ACCOUNT) CalloutKind.WARNING else CalloutKind.INFO,
    )
    if (action == AccountAction.CHANGE_EMAIL) {
        OutlinedTextField(
            newEmail,
            { newEmail = it },
            label = { Text(stringResource(R.string.account_new_email)) },
            modifier = Modifier.fillMaxWidth(),
        )
    }
    if (action != AccountAction.EXPORT) ProofInput(action, secret, { secret = it }, codeSent, model)
    problem?.let { Callout(stringResource(R.string.account_problem, problemName(it)), kind = CalloutKind.ERROR) }
    Button(
        onClick = {
            val proof = if (codeSent) ReauthProof.EmailCode(secret) else ReauthProof.Password(secret)
            when (action) {
                AccountAction.DELETE_ACCOUNT -> model.delete(proof)
                AccountAction.CHANGE_EMAIL -> model.changeEmail(newEmail, proof)
                AccountAction.SIGN_OUT_OTHERS -> model.signOutOthers(secret)
                AccountAction.EXPORT -> model.export()
            }
        },
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
        shape = MaterialTheme.shapes.large,
    ) { Text(stringResource(R.string.account_continue)) }
    TextButton(onClick = model::cancel) { Text(stringResource(R.string.cancel)) }
}

@Composable
private fun ProofInput(
    action: AccountAction,
    secret: String,
    onSecret: (String) -> Unit,
    codeSent: Boolean,
    model: AccountViewModel,
) {
    if (codeSent) {
        OutlinedTextField(
            secret,
            onSecret,
            label = { Text(stringResource(R.string.account_email_code)) },
            modifier = Modifier.fillMaxWidth(),
        )
        return
    }
    PasswordField(secret, onSecret, stringResource(R.string.account_password), Modifier.fillMaxWidth())
    if (action == AccountAction.DELETE_ACCOUNT || action == AccountAction.CHANGE_EMAIL) {
        TextButton(onClick = model::sendCode) { Text(stringResource(R.string.account_send_code)) }
    }
}

@Composable
private fun DoneText(result: AccountActionResult) {
    Callout(
        when (result) {
            is AccountActionResult.AccountDeleted -> {
                stringResource(R.string.account_done_deleted)
            }

            is AccountActionResult.EmailChanged -> {
                stringResource(R.string.account_done_email, result.email)
            }

            is AccountActionResult.SignedOutOthers -> {
                stringResource(
                    R.string.account_done_others,
                    result.revoked,
                    stringResource(if (result.rotated) R.string.yes else R.string.no),
                )
            }

            is AccountActionResult.Exported -> {
                stringResource(R.string.account_done_export)
            }
        },
        kind = CalloutKind.SUCCESS,
    )
}

/** A short, non-secret name of a problem (its code, never server text). */
private fun problemName(problem: AccountProblem): String =
    when (problem) {
        is AccountProblem.Server -> problem.code
        else -> problem::class.simpleName.orEmpty().lowercase()
    }
