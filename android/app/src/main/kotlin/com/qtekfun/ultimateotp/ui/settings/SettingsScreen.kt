// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.settings

import android.app.ActivityManager
import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.vault.ImportOutcome
import com.qtekfun.ultimateotp.core.vault.VaultTransfer
import com.qtekfun.ultimateotp.util.AppSettings
import com.qtekfun.ultimateotp.util.Settings
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onSync: () -> Unit,
    model: SettingsViewModel = hiltViewModel(),
) {
    val settings by model.settings.collectAsState()
    val status by model.status.collectAsState()
    var exportPassword by remember { mutableStateOf<String?>(null) }
    var askExportPassword by remember { mutableStateOf(false) }
    var confirmPlain by remember { mutableStateOf(false) }
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
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                    ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.section_security), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.lock_timeout, settings.lockTimeoutSeconds))
            LOCK_CHOICES.forEach { s ->
                TextButton(onClick = { model.setLockTimeout(s) }) { Text(stringResource(R.string.lock_after, s)) }
            }
            HorizontalDivider()
            Text(stringResource(R.string.section_backup), style = MaterialTheme.typography.titleMedium)
            Button(
                onClick = { askExportPassword = true },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.export_encrypted)) }
            OutlinedButton(
                onClick = { confirmPlain = true },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.export_plain)) }
            OutlinedButton(onClick = { importSource.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.import_file))
            }
            status?.let { Text(statusText(it)) }
            HorizontalDivider()
            Text(stringResource(R.string.section_sync), style = MaterialTheme.typography.titleMedium)
            Button(onClick = onSync, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.sync_open)) }
        }
    }
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
                }) { Text(stringResource(R.string.export_anyway)) }
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
    }

/** Asks for a password; with [confirm] it must be typed twice and be at least 8 characters. */
@Composable
fun PasswordDialog(
    title: String,
    confirm: Boolean,
    onDismiss: () -> Unit,
    onPassword: (String) -> Unit,
) {
    var first by remember { mutableStateOf("") }
    var second by remember { mutableStateOf("") }
    val ok = if (confirm) first.length >= MIN_PASSWORD && first == second else first.isNotEmpty()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(first, {
                    first = it
                }, label = { Text(stringResource(R.string.password)) }, visualTransformation = PasswordVisualTransformation())
                if (confirm) {
                    OutlinedTextField(
                        second,
                        { second = it },
                        label = { Text(stringResource(R.string.password_repeat)) },
                        visualTransformation = PasswordVisualTransformation(),
                    )
                }
            }
        },
        confirmButton = { TextButton(enabled = ok, onClick = { onPassword(first) }) { Text(stringResource(R.string.ok)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

private const val MIN_PASSWORD = 8
private val LOCK_CHOICES = listOf(0, 30, 60, 300)
