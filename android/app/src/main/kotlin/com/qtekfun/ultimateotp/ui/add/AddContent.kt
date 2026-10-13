// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.add

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.otp.Base32
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.ui.codes.AddMode
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.CalloutKind
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import com.qtekfun.ultimateotp.ui.settings.PasswordDialog
import com.qtekfun.ultimateotp.ui.settings.TransferStatus
import com.qtekfun.ultimateotp.ui.theme.Space

private const val DEFAULT_DIGITS = "6"
private const val DEFAULT_PERIOD = "30"

/** The add screen, stateless: three modes in a segmented switch, each a plain column. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddContent(
    mode: AddMode,
    onMode: (AddMode) -> Unit,
    invalid: Boolean,
    cameraGranted: Boolean,
    onAllowCamera: () -> Unit,
    onPickImage: () -> Unit,
    onPickFile: () -> Unit,
    fileStatus: TransferStatus?,
    onFilePassword: (String) -> Unit,
    onFilePasswordDismiss: () -> Unit,
    onText: (String) -> Unit,
    onAddManual: (OtpParams) -> Unit,
    onBack: () -> Unit,
    scanner: @Composable (Modifier) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowScaffold(title = stringResource(R.string.add_account), onBack = onBack, modifier = modifier) {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            val modes = AddMode.entries
            modes.forEachIndexed { index, m ->
                SegmentedButton(
                    selected = mode == m,
                    onClick = { onMode(m) },
                    shape = SegmentedButtonDefaults.itemShape(index, modes.size),
                ) {
                    Text(
                        stringResource(
                            when (m) {
                                AddMode.SCAN -> R.string.tab_scan
                                AddMode.MANUAL -> R.string.tab_manual
                                AddMode.IMPORT -> R.string.tab_import
                            },
                        ),
                        maxLines = 1,
                    )
                }
            }
        }
        if (invalid) Callout(stringResource(R.string.invalid_code), kind = CalloutKind.ERROR)
        when (mode) {
            AddMode.SCAN -> ScanMode(cameraGranted, onAllowCamera, onPickImage, scanner)
            AddMode.MANUAL -> ManualMode(onAddManual)
            AddMode.IMPORT -> ImportMode(onPickFile, onText)
        }
    }
    when (fileStatus) {
        TransferStatus.NeedsPassword, TransferStatus.WrongPassword -> {
            PasswordDialog(
                title =
                    stringResource(
                        if (fileStatus == TransferStatus.WrongPassword) R.string.wrong_password else R.string.import_password_title,
                    ),
                confirm = false,
                onDismiss = onFilePasswordDismiss,
                onPassword = onFilePassword,
            )
        }

        TransferStatus.Failed -> {
            PasswordlessFailure(onFilePasswordDismiss)
        }

        else -> {}
    }
}

@Composable
private fun PasswordlessFailure(onDismiss: () -> Unit) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        text = { Text(stringResource(R.string.transfer_failed)) },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.ok)) } },
    )
}

@Composable
private fun ScanMode(
    granted: Boolean,
    onAllow: () -> Unit,
    onPickImage: () -> Unit,
    scanner: @Composable (Modifier) -> Unit,
) {
    if (granted) {
        Surface(
            Modifier.fillMaxWidth().widthIn(max = 420.dp).aspectRatio(1f),
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surfaceContainer,
            border = BorderStroke(2.dp, MaterialTheme.colorScheme.primary),
        ) {
            scanner(Modifier.fillMaxWidth().aspectRatio(1f).clip(MaterialTheme.shapes.extraLarge))
        }
        Text(
            stringResource(R.string.scan_hint),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    } else {
        Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
            Column(Modifier.padding(Space.Xl), verticalArrangement = Arrangement.spacedBy(Space.Lg)) {
                Icon(Icons.Filled.QrCodeScanner, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text(stringResource(R.string.camera_rationale), style = MaterialTheme.typography.bodyLarge)
                Button(onClick = onAllow) { Text(stringResource(R.string.allow_camera)) }
            }
        }
    }
    OutlinedButton(onClick = onPickImage, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.Image, contentDescription = null)
        Text(stringResource(R.string.scan_image), modifier = Modifier.padding(start = Space.Sm))
    }
}

@Composable
private fun ImportMode(
    onPickFile: () -> Unit,
    onText: (String) -> Unit,
) {
    var text by rememberRetainedText("add-import-text")
    FilledTonalButton(onClick = onPickFile, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.FileUpload, contentDescription = null)
        Text(stringResource(R.string.import_file), modifier = Modifier.padding(start = Space.Sm))
    }
    Text(
        stringResource(R.string.import_file_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        label = { Text(stringResource(R.string.paste_hint)) },
        modifier = Modifier.fillMaxWidth(),
        minLines = 4,
        shape = MaterialTheme.shapes.medium,
    )
    Button(onClick = { onText(text) }, enabled = text.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.add))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ManualMode(onAdd: (OtpParams) -> Unit) {
    var issuer by rememberSaveable { mutableStateOf("") }
    var label by rememberSaveable { mutableStateOf("") }
    var secret by rememberRetainedText("add-secret")
    var advanced by rememberSaveable { mutableStateOf(false) }
    var type by rememberSaveable { mutableStateOf(OtpType.TOTP) }
    var algorithm by rememberSaveable { mutableStateOf(OtpAlgorithm.SHA1) }
    var digits by rememberSaveable { mutableStateOf(DEFAULT_DIGITS) }
    var period by rememberSaveable { mutableStateOf(DEFAULT_PERIOD) }
    val secretOk = Base32.isValid(secret)
    val valid =
        secretOk && digits.toIntOrNull() in OtpParams.MIN_DIGITS..OtpParams.MAX_DIGITS && (period.toIntOrNull() ?: 0) > 0
    Row(horizontalArrangement = Arrangement.spacedBy(Space.Lg), verticalAlignment = Alignment.CenterVertically) {
        IssuerAvatar(issuer, label, size = 56.dp)
        Text(
            issuer.ifBlank { stringResource(R.string.issuer_preview) },
            style = MaterialTheme.typography.titleMedium,
            color = if (issuer.isBlank()) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
        )
    }
    OutlinedTextField(
        issuer,
        { issuer = it },
        label = { Text(stringResource(R.string.issuer)) },
        singleLine = true,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        label,
        { label = it },
        label = { Text(stringResource(R.string.account)) },
        singleLine = true,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        secret,
        { secret = it },
        label = { Text(stringResource(R.string.secret)) },
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
        isError = secret.isNotEmpty() && !secretOk,
        supportingText = { if (secret.isNotEmpty() && !secretOk) Text(stringResource(R.string.secret_invalid)) },
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    )
    TextButton(onClick = { advanced = !advanced }) {
        Text(stringResource(R.string.advanced_options))
        Icon(if (advanced) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore, contentDescription = null)
    }
    if (advanced) {
        Row(horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
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
        Row(horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
            OutlinedTextField(
                digits,
                { digits = it.filter(Char::isDigit).take(2) },
                label = { Text(stringResource(R.string.digits)) },
                singleLine = true,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.weight(1f),
            )
            OutlinedTextField(
                period,
                { period = it.filter(Char::isDigit).take(5) },
                label = { Text(stringResource(R.string.period)) },
                singleLine = true,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.weight(1f),
            )
        }
    }
    Button(
        enabled = valid,
        modifier = Modifier.fillMaxWidth(),
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
            singleLine = true,
            label = { Text(title) },
            shape = MaterialTheme.shapes.medium,
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
