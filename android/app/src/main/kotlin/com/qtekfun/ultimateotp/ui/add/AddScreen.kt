// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.add

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.PlainListImport
import com.qtekfun.ultimateotp.core.vault.ImportOutcome
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultTransfer
import com.qtekfun.ultimateotp.ui.codes.AddMode
import com.qtekfun.ultimateotp.ui.settings.TransferStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/** What happened to a scanned or pasted text. */
sealed interface AddResult {
    data class Added(
        val count: Int,
        val duplicates: Int,
    ) : AddResult

    data object Invalid : AddResult

    /** A `uotp://` link: pairing or enrollment, handled by the sync screen. */
    data class SyncLink(
        val link: String,
    ) : AddResult
}

@HiltViewModel
class AddViewModel
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val vault: VaultRepository,
        private val transfer: VaultTransfer,
    ) : ViewModel() {
        private val _result = MutableStateFlow<AddResult?>(null)
        val result: StateFlow<AddResult?> = _result

        /** Status of the last file import started here (password needed, wrong password, failed). */
        val fileStatus = MutableStateFlow<TransferStatus?>(null)
        private var pendingFile: Uri? = null

        fun submitText(text: String) {
            if (text.trim().startsWith("uotp://", ignoreCase = true)) {
                _result.value = AddResult.SyncLink(text.trim())
                return
            }
            val parsed = PlainListImport.parse(text)
            if (parsed.accounts.isEmpty()) {
                _result.value = AddResult.Invalid
                return
            }
            viewModelScope.launch {
                val summary = vault.import(parsed.accounts)
                _result.value = AddResult.Added(summary.added, summary.duplicates)
            }
        }

        fun addManual(params: OtpParams) =
            viewModelScope.launch {
                vault.add(params)
                _result.value = AddResult.Added(1, 0)
            }

        /** An UltimateOTP or Ente export, or an otpauth list, picked as a file. */
        fun importFile(
            source: Uri,
            password: String?,
        ) = viewModelScope.launch {
            pendingFile = source
            fileStatus.value = TransferStatus.Working
            val outcome =
                runCatching {
                    val bytes = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(source)?.use { it.readBytes() } }
                    bytes?.let { transfer.import(it, password) }
                }.getOrNull()
            when (outcome) {
                is ImportOutcome.Imported -> {
                    fileStatus.value = null
                    _result.value = AddResult.Added(outcome.summary.added, outcome.summary.duplicates)
                }

                is ImportOutcome.PasswordRequired -> {
                    fileStatus.value = TransferStatus.NeedsPassword
                }

                ImportOutcome.WrongPassword -> {
                    fileStatus.value = TransferStatus.WrongPassword
                }

                else -> {
                    fileStatus.value = TransferStatus.Failed
                }
            }
        }

        fun importFileWithPassword(password: String) {
            pendingFile?.let { importFile(it, password) }
        }

        fun clearFileStatus() {
            fileStatus.value = null
        }

        fun consumed() {
            _result.value = null
        }
    }

/** The stateful add screen: opened by the add sheet with a [mode], or by a link. */
@Composable
fun AddScreen(
    initialLink: String,
    initialMode: AddMode,
    onDone: () -> Unit,
    onSyncLink: (String) -> Unit,
    model: AddViewModel = hiltViewModel(),
) {
    var mode by androidx.compose.runtime.saveable
        .rememberSaveable { mutableStateOf(initialMode) }
    val result by model.result.collectAsState()
    val fileStatus by model.fileStatus.collectAsState()
    val context = LocalContext.current
    LaunchedEffect(initialLink) { if (initialLink.isNotBlank()) model.submitText(initialLink) }
    LaunchedEffect(result) {
        when (val r = result) {
            is AddResult.Added -> {
                model.consumed()
                onDone()
            }

            is AddResult.SyncLink -> {
                model.consumed()
                onSyncLink(r.link)
            }

            else -> {}
        }
    }
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    val imagePicker =
        rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
            val bitmap = uri?.let { u -> context.contentResolver.openInputStream(u)?.use { BitmapFactory.decodeStream(it) } }
            model.submitText(bitmap?.let { QrDecoder.decode(it) }.orEmpty())
        }
    val filePicker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) model.importFile(uri, null)
        }
    AddContent(
        mode = mode,
        onMode = { mode = it },
        invalid = result == AddResult.Invalid,
        cameraGranted = granted,
        onAllowCamera = { permission.launch(Manifest.permission.CAMERA) },
        onPickImage = { imagePicker.launch("image/*") },
        onPickFile = { filePicker.launch(arrayOf("*/*")) },
        fileStatus = fileStatus,
        onFilePassword = model::importFileWithPassword,
        onFilePasswordDismiss = model::clearFileStatus,
        onText = model::submitText,
        onAddManual = model::addManual,
        onBack = onDone,
        scanner = { QrScanner(onResult = model::submitText, modifier = it) },
        modifier = Modifier,
    )
}
