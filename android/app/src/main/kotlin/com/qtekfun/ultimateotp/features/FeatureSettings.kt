// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.view.autofill.AutofillManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.support.lock.LockTimeout
import com.qtekfun.ultimateotp.util.AppSettings
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject
import android.provider.Settings as AndroidSettings

@HiltViewModel
class FeatureSettingsViewModel
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val appSettings: AppSettings,
        private val diagnostics: DiagnosticsLog,
    ) : ViewModel() {
        val lockTimeout: StateFlow<LockTimeout> =
            appSettings.settings
                .map { LockTimeout.fromStored(it.lockTimeoutSeconds) }
                .stateIn(viewModelScope, SharingStarted.Eagerly, LockTimeout.DEFAULT)

        fun setLockTimeout(value: LockTimeout) = viewModelScope.launch { appSettings.update { it.copy(lockTimeoutSeconds = value.stored) } }

        fun autofillEnabled(): Boolean = context.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true

        /** The error log text (header with build and R8 map id, then the records). */
        fun logText(): String = diagnostics.export()

        fun saveLog(target: Uri) =
            viewModelScope.launch {
                val text = diagnostics.export()
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(target, "wt")?.use { it.write(text.toByteArray()) } }
            }

        fun clearLog() = diagnostics.clear()
    }

/**
 * The settings of the features added with the logic (lock timeout, autofill, error log, trash,
 * account), as one block for the settings screen to include.
 */
@Composable
fun FeatureSettingsSection(
    onTrash: () -> Unit,
    onAccount: () -> Unit,
    onAutofillAssociations: () -> Unit,
    model: FeatureSettingsViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val timeout by model.lockTimeout.collectAsState()
    var picking by remember { mutableStateOf(false) }
    val saveLog =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri -> uri?.let(model::saveLog) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // Inactivity lock: one list preference.
        OutlinedButton(onClick = { picking = true }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.lock_timeout_title) + ": " + stringResource(label(timeout)))
        }
        HorizontalDivider()
        Text(stringResource(R.string.section_autofill), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(if (model.autofillEnabled()) R.string.autofill_state_on else R.string.autofill_state_off))
        OutlinedButton(
            onClick = {
                val intent =
                    Intent(AndroidSettings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${context.packageName}"))
                runCatching { context.startActivity(intent) }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.autofill_enable)) }
        OutlinedButton(onClick = onAutofillAssociations, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.autofill_associations))
        }
        HorizontalDivider()
        OutlinedButton(onClick = onTrash, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.trash)) }
        OutlinedButton(onClick = onAccount, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.account_settings)) }
        HorizontalDivider()
        Text(stringResource(R.string.section_diagnostics), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.diagnostics_help))
        OutlinedButton(
            onClick = {
                val send =
                    Intent(Intent.ACTION_SEND)
                        .setType("text/plain")
                        .putExtra(Intent.EXTRA_SUBJECT, "UltimateOTP error log")
                        .putExtra(Intent.EXTRA_TEXT, model.logText())
                runCatching { context.startActivity(Intent.createChooser(send, null)) }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.diagnostics_share)) }
        OutlinedButton(onClick = { saveLog.launch("ultimateotp-error-log.txt") }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.diagnostics_save))
        }
        OutlinedButton(onClick = model::clearLog, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.diagnostics_clear)) }
    }
    if (picking) {
        AlertDialog(
            onDismissRequest = { picking = false },
            title = { Text(stringResource(R.string.lock_timeout_title)) },
            text = {
                Column(Modifier.selectableGroup()) {
                    for (choice in LockTimeout.entries) {
                        androidx.compose.foundation.layout.Row(
                            Modifier.fillMaxWidth().selectable(selected = choice == timeout, onClick = {
                                model.setLockTimeout(choice)
                                picking = false
                            }),
                        ) {
                            RadioButton(selected = choice == timeout, onClick = null)
                            Text(stringResource(label(choice)), Modifier.padding(start = 8.dp))
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { picking = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

private fun label(t: LockTimeout): Int =
    when (t) {
        LockTimeout.IMMEDIATELY -> R.string.lock_choice_immediately
        LockTimeout.SECONDS_30 -> R.string.lock_choice_30s
        LockTimeout.MINUTE_1 -> R.string.lock_choice_1m
        LockTimeout.MINUTES_5 -> R.string.lock_choice_5m
        LockTimeout.NEVER -> R.string.lock_choice_never
    }
