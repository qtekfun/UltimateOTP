// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.add

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.auth.GateResult
import com.qtekfun.ultimateotp.core.otp.Base32
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.otp.PlainListImport
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
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
        private val vault: VaultRepository,
        private val gate: AuthGate,
    ) : ViewModel() {
        private val _result = MutableStateFlow<AddResult?>(null)
        val result: StateFlow<AddResult?> = _result

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
                val done = gate.attempt { vault.import(parsed.accounts) }
                if (done is GateResult.Done) _result.value = AddResult.Added(done.value.added, done.value.duplicates)
            }
        }

        fun addManual(params: OtpParams) =
            viewModelScope.launch {
                if (gate.attempt { vault.add(params) } is GateResult.Done) _result.value = AddResult.Added(1, 0)
            }

        fun consumed() {
            _result.value = null
        }
    }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddScreen(
    initialLink: String,
    onDone: () -> Unit,
    onSyncLink: (String) -> Unit,
    model: AddViewModel = hiltViewModel(),
) {
    var tab by remember { mutableIntStateOf(0) }
    val result by model.result.collectAsState()
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
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.add_account)) },
                navigationIcon = {
                    IconButton(onClick = onDone) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).verticalScroll(rememberScrollState())) {
            PrimaryTabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.tab_scan)) })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.tab_manual)) })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text(stringResource(R.string.tab_paste)) })
            }
            if (result == AddResult.Invalid) {
                Text(stringResource(R.string.invalid_code), color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp))
            }
            when (tab) {
                0 -> ScanTab(onText = model::submitText)
                1 -> ManualTab(onAdd = model::addManual)
                else -> PasteTab(onText = model::submitText)
            }
        }
    }
}

@Composable
private fun ScanTab(onText: (String) -> Unit) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    val picker =
        rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
            val bitmap = uri?.let { u -> context.contentResolver.openInputStream(u)?.use { BitmapFactory.decodeStream(it) } }
            val text = bitmap?.let { QrDecoder.decode(it) }
            onText(text.orEmpty())
        }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (granted) {
            QrScanner(onResult = onText, modifier = Modifier.fillMaxWidth().aspectRatio(1f))
        } else {
            Text(stringResource(R.string.camera_rationale))
            Button(onClick = { permission.launch(Manifest.permission.CAMERA) }) { Text(stringResource(R.string.allow_camera)) }
        }
        OutlinedButton(onClick = { picker.launch("image/*") }) { Text(stringResource(R.string.scan_image)) }
    }
}

@Composable
private fun PasteTab(onText: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text(stringResource(R.string.paste_hint)) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
        )
        Button(onClick = { onText(text) }, enabled = text.isNotBlank()) { Text(stringResource(R.string.add)) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ManualTab(onAdd: (OtpParams) -> Unit) {
    var issuer by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var type by remember { mutableStateOf(OtpType.TOTP) }
    var algorithm by remember { mutableStateOf(OtpAlgorithm.SHA1) }
    var digits by remember { mutableStateOf("6") }
    var period by remember { mutableStateOf("30") }
    val valid =
        Base32.isValid(secret) && digits.toIntOrNull() in OtpParams.MIN_DIGITS..OtpParams.MAX_DIGITS &&
            (period.toIntOrNull() ?: 0) > 0
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(issuer, { issuer = it }, label = { Text(stringResource(R.string.issuer)) }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(label, { label = it }, label = { Text(stringResource(R.string.account)) }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            secret,
            { secret = it },
            label = { Text(stringResource(R.string.secret)) },
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
            isError = secret.isNotEmpty() && !Base32.isValid(secret),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Choice(stringResource(R.string.type), OtpType.entries, type, { it.name }, { type = it }, Modifier.weight(1f))
            Choice(
                stringResource(R.string.algorithm),
                OtpAlgorithm.entries,
                algorithm,
                { it.name },
                { algorithm = it },
                Modifier.weight(1f),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(digits, { digits = it }, label = { Text(stringResource(R.string.digits)) }, modifier = Modifier.weight(1f))
            OutlinedTextField(period, { period = it }, label = { Text(stringResource(R.string.period)) }, modifier = Modifier.weight(1f))
        }
        Button(
            enabled = valid,
            onClick = {
                onAdd(
                    OtpParams(
                        type = type,
                        secret = Base32.decode(secret),
                        algorithm = if (type == OtpType.STEAM) OtpAlgorithm.SHA1 else algorithm,
                        digits = if (type == OtpType.STEAM) OtpParams.STEAM_DIGITS else digits.toInt(),
                        period = period.toInt(),
                        issuer = issuer.trim(),
                        label = label.trim(),
                    ),
                )
            },
        ) { Text(stringResource(R.string.add)) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun <T> Choice(
    title: String,
    options: List<T>,
    selected: T,
    name: (T) -> String,
    onSelect: (T) -> Unit,
    modifier: Modifier,
) {
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }, modifier = modifier) {
        OutlinedTextField(
            value = name(selected),
            onValueChange = {},
            readOnly = true,
            label = { Text(title) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(open) },
            modifier = Modifier.menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { option ->
                DropdownMenuItem(text = { Text(name(option)) }, onClick = {
                    onSelect(option)
                    open = false
                })
            }
        }
    }
}
