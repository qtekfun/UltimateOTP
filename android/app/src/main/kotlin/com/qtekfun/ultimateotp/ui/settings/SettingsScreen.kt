// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.settings

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.BuildConfig
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.vault.ImportOutcome
import com.qtekfun.ultimateotp.core.vault.VaultTransfer
import com.qtekfun.ultimateotp.features.FeatureSettingsViewModel
import com.qtekfun.ultimateotp.ui.components.PasswordField
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import com.qtekfun.ultimateotp.util.AppLanguage
import com.qtekfun.ultimateotp.util.AppSettings
import com.qtekfun.ultimateotp.util.Settings
import com.qtekfun.ultimateotp.util.ThemeMode
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject
import android.provider.Settings as AndroidSettings

/** One-line status of the last export or import. */
sealed interface TransferStatus {
    data object Working : TransferStatus

    data object Exported : TransferStatus

    data class Imported(
        val added: Int,
        val duplicates: Int,
        val rejected: Int,
    ) : TransferStatus

    data object NeedsPassword : TransferStatus

    data object WrongPassword : TransferStatus

    data object Failed : TransferStatus

    /** A file of an unsupported variant, with the reason in one fixed line (no file content). */
    data class Unreadable(
        val reason: String,
    ) : TransferStatus
}

@HiltViewModel
class SettingsViewModel
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val transfer: VaultTransfer,
        private val appSettings: AppSettings,
    ) : ViewModel() {
        val settings: StateFlow<Settings> = appSettings.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())
        val status = MutableStateFlow<TransferStatus?>(null)
        private var pendingImport: Uri? = null

        fun setLockTimeout(seconds: Int) = viewModelScope.launch { appSettings.update { it.copy(lockTimeoutSeconds = seconds) } }

        fun setClipboardClear(seconds: Int) = viewModelScope.launch { appSettings.update { it.copy(clipboardClearSeconds = seconds) } }

        fun setThemeMode(mode: ThemeMode) = viewModelScope.launch { appSettings.update { it.copy(themeMode = mode) } }

        fun setAmoled(on: Boolean) = viewModelScope.launch { appSettings.update { it.copy(amoled = on) } }

        fun setDynamicColor(on: Boolean) = viewModelScope.launch { appSettings.update { it.copy(dynamicColor = on) } }

        fun setGridLayout(on: Boolean) = viewModelScope.launch { appSettings.update { it.copy(gridLayout = on) } }

        fun setHideCodes(on: Boolean) = viewModelScope.launch { appSettings.update { it.copy(hideCodes = on) } }

        /** Argon2id starts at the rung that fits in free memory (crypto-format.md §4.1). */
        private fun ladder(): List<Pair<Long, Long>> {
            val info = ActivityManager.MemoryInfo()
            context.getSystemService(ActivityManager::class.java)?.getMemoryInfo(info)
            return PasswordKdf.ladderFor(info.availMem)
        }

        fun exportEncrypted(
            target: Uri,
            password: String,
        ) = run {
            val bytes = transfer.exportEncrypted(password, ladder())
            write(target, bytes)
        }

        fun exportPlain(target: Uri) = run { write(target, transfer.exportPlain().toByteArray()) }

        private suspend fun write(
            target: Uri,
            bytes: ByteArray,
        ) {
            withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(target, "wt")?.use { it.write(bytes) } }
            status.value = TransferStatus.Exported
        }

        fun import(
            source: Uri,
            password: String?,
        ) = run {
            pendingImport = source
            val bytes = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(source)?.use { it.readBytes() } }
            status.value =
                when (val outcome = bytes?.let { transfer.import(it, password) }) {
                    is ImportOutcome.Imported -> {
                        TransferStatus.Imported(
                            outcome.summary.added,
                            outcome.summary.duplicates,
                            outcome.summary.rejected,
                        )
                    }

                    is ImportOutcome.PasswordRequired -> {
                        TransferStatus.NeedsPassword
                    }

                    ImportOutcome.WrongPassword -> {
                        TransferStatus.WrongPassword
                    }

                    is ImportOutcome.Unreadable -> {
                        TransferStatus.Unreadable(outcome.reason)
                    }

                    else -> {
                        TransferStatus.Failed
                    }
                }
        }

        fun importWithPassword(password: String) {
            pendingImport?.let { import(it, password) }
        }

        private fun run(block: suspend () -> Unit) =
            viewModelScope.launch {
                status.value = TransferStatus.Working
                // Any I/O or crypto failure ends as one generic message (never with file contents).
                runCatching { block() }.onFailure { status.value = TransferStatus.Failed }
            }
    }

@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onSync: () -> Unit,
    onSessions: () -> Unit,
    onTrash: () -> Unit,
    onAccount: () -> Unit,
    onAutofillAssociations: () -> Unit,
    model: SettingsViewModel = hiltViewModel(),
    features: FeatureSettingsViewModel = hiltViewModel(),
) {
    val settings by model.settings.collectAsState()
    val status by model.status.collectAsState()
    val context = androidx.compose.ui.platform.LocalContext.current
    var language by remember { mutableStateOf(AppLanguage.current(context)) }
    var exportPassword by remember { mutableStateOf<String?>(null) }
    var askExportPassword by rememberSaveable { mutableStateOf(false) }
    var confirmPlain by rememberSaveable { mutableStateOf(false) }
    val encryptedTarget =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            val pw = exportPassword
            if (uri != null && pw != null) model.exportEncrypted(uri, pw)
            exportPassword = null
        }
    val plainTarget =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            if (uri != null) model.exportPlain(uri)
        }
    val importSource =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) model.import(uri, null)
        }
    val saveLog =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri -> uri?.let(features::saveLog) }
    SettingsContent(
        settings = settings,
        statusText = status?.let { statusText(it) },
        version = BuildConfig.VERSION_NAME,
        language = language,
        actions =
            SettingsActions(
                onBack = onBack,
                onSync = onSync,
                onSessions = onSessions,
                onLockTimeout = { model.setLockTimeout(it) },
                onClipboardClear = { model.setClipboardClear(it) },
                onHideCodes = { model.setHideCodes(it) },
                onThemeMode = { model.setThemeMode(it) },
                onAmoled = { model.setAmoled(it) },
                onDynamicColor = { model.setDynamicColor(it) },
                onGridLayout = { model.setGridLayout(it) },
                onLanguage = { tag ->
                    language = tag
                    (context as? android.app.Activity)?.let { AppLanguage.set(it, tag) }
                },
                onExportEncrypted = { askExportPassword = true },
                onExportPlain = { confirmPlain = true },
                onImport = { importSource.launch(arrayOf("*/*")) },
                onTrash = onTrash,
                onAccount = onAccount,
                onAutofillSettings = {
                    val intent =
                        Intent(AndroidSettings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, "package:${context.packageName}".toUri())
                    runCatching { context.startActivity(intent) }
                },
                onAutofillAssociations = onAutofillAssociations,
                onShareLog = {
                    val send =
                        Intent(Intent.ACTION_SEND)
                            .setType("text/plain")
                            .putExtra(Intent.EXTRA_SUBJECT, "UltimateOTP error log")
                            .putExtra(Intent.EXTRA_TEXT, features.logText())
                    runCatching { context.startActivity(Intent.createChooser(send, null)) }
                },
                onSaveLog = { saveLog.launch("ultimateotp-error-log.txt") },
                onClearLog = features::clearLog,
            ),
        autofillEnabled = features.autofillEnabled(),
    )
    if (askExportPassword) {
        PasswordDialog(
            title = stringResource(R.string.export_password_title),
            confirm = true,
            onDismiss = { askExportPassword = false },
            onPassword = {
                askExportPassword = false
                exportPassword = it
                encryptedTarget.launch("ultimateotp-export.uotp")
            },
        )
    }
    if (status == TransferStatus.NeedsPassword || status == TransferStatus.WrongPassword) {
        PasswordDialog(
            title = stringResource(if (status == TransferStatus.WrongPassword) R.string.wrong_password else R.string.import_password_title),
            confirm = false,
            onDismiss = { model.status.value = null },
            onPassword = model::importWithPassword,
        )
    }
    if (confirmPlain) {
        AlertDialog(
            onDismissRequest = { confirmPlain = false },
            title = { Text(stringResource(R.string.export_plain)) },
            text = { Text(stringResource(R.string.export_plain_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmPlain = false
                    plainTarget.launch("ultimateotp-export.txt")
                }) { Text(stringResource(R.string.export_anyway), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmPlain = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun statusText(status: TransferStatus): String =
    when (status) {
        TransferStatus.Working -> stringResource(R.string.working)
        TransferStatus.Exported -> stringResource(R.string.exported)
        is TransferStatus.Imported -> stringResource(R.string.imported, status.added, status.duplicates, status.rejected)
        TransferStatus.NeedsPassword -> stringResource(R.string.import_password_title)
        TransferStatus.WrongPassword -> stringResource(R.string.wrong_password)
        TransferStatus.Failed -> stringResource(R.string.transfer_failed)
        is TransferStatus.Unreadable -> status.reason
    }

/** Asks for a password; with [confirm] it must be typed twice and be at least 8 characters. */
@Composable
fun PasswordDialog(
    title: String,
    confirm: Boolean,
    onDismiss: () -> Unit,
    onPassword: (String) -> Unit,
) {
    var first by rememberRetainedText("dialog-password")
    var second by rememberRetainedText("dialog-password-repeat")
    val ok = if (confirm) first.length >= MIN_PASSWORD && first == second else first.isNotEmpty()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PasswordField(first, { first = it }, stringResource(R.string.password))
                if (confirm) {
                    PasswordField(second, { second = it }, stringResource(R.string.password_repeat))
                }
            }
        },
        confirmButton = { TextButton(enabled = ok, onClick = { onPassword(first) }) { Text(stringResource(R.string.ok)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** A dialog with one radio row per option. */
@Composable
fun <T> ChoiceDialog(
    title: String,
    options: List<Pair<T, String>>,
    selected: T,
    onSelect: (T) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                options.forEach { (value, label) ->
                    Row(
                        Modifier
                            .fillMaxWidthClickable { onSelect(value) }
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = value == selected, onClick = null)
                        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

private const val MIN_PASSWORD = 8

/** The label of a duration setting: Immediately, 30 seconds, 1 minute, 5 minutes. */
@Composable
fun durationText(seconds: Int): String =
    when {
        seconds < 0 -> {
            stringResource(R.string.lock_choice_never)
        }

        seconds == 0 -> {
            stringResource(R.string.duration_immediately)
        }

        seconds % SECONDS_PER_MINUTE == 0 -> {
            androidx.compose.ui.res.pluralStringResource(
                R.plurals.duration_minutes,
                seconds / SECONDS_PER_MINUTE,
                seconds / SECONDS_PER_MINUTE,
            )
        }

        else -> {
            androidx.compose.ui.res
                .pluralStringResource(R.plurals.duration_seconds, seconds, seconds)
        }
    }

private const val SECONDS_PER_MINUTE = 60

private fun Modifier.fillMaxWidthClickable(onClick: () -> Unit): Modifier = this.then(Modifier.fillMaxWidth()).clickable(onClick = onClick)
