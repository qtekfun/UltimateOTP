// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Label
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.components.SettingsRow
import com.qtekfun.ultimateotp.ui.theme.Space

/** The sheets and dialogs of the codes screen: add, account menu, tags, delete confirmation. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CodesSheets(
    items: List<VaultItem>,
    ui: CodesUi,
    on: CodesActions,
) {
    if (ui.addSheet) {
        ModalBottomSheet(onDismissRequest = { on.onAddSheet(false) }, sheetState = rememberModalBottomSheetState()) {
            AddSheetContent(onChoose = on.onAdd)
        }
    }
    val menuItem = items.firstOrNull { it.id == ui.menuId }
    if (menuItem != null) {
        ModalBottomSheet(onDismissRequest = { on.onMenu(null) }, sheetState = rememberModalBottomSheetState()) {
            ItemMenuContent(
                item = menuItem,
                onEdit = { on.onEdit(menuItem.id) },
                onPin = { on.onTogglePin(menuItem) },
                onTags = {
                    on.onMenu(null)
                    on.onTagsDialog(menuItem.id)
                },
                onNext = {
                    on.onMenu(null)
                    on.onNext(menuItem)
                },
                onDelete = {
                    on.onMenu(null)
                    on.onDeleteDialog(menuItem.id)
                },
            )
        }
    }
    items.firstOrNull { it.id == ui.tagsId }?.let { item ->
        TagsDialog(item, allTags(items), onDismiss = { on.onTagsDialog(null) }, onSave = { on.onSetTags(item, it) })
    }
    items.firstOrNull { it.id == ui.deleteId }?.let { item ->
        DeleteDialog(item, onDismiss = { on.onDeleteDialog(null) }, onConfirm = { on.onDelete(item) })
    }
}

/** Scan a QR code, enter a key, or import: the three ways to add accounts. */
@Composable
fun AddSheetContent(onChoose: (AddMode) -> Unit) {
    Column(Modifier.navigationBarsPadding().padding(bottom = Space.Lg)) {
        Text(
            stringResource(R.string.add_account),
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(horizontal = Space.Lg, vertical = Space.Sm),
        )
        SettingsRow(
            Icons.Filled.QrCodeScanner,
            stringResource(R.string.add_scan_title),
            subtitle = stringResource(R.string.add_scan_body),
            onClick = { onChoose(AddMode.SCAN) },
        )
        SettingsRow(
            Icons.Filled.Keyboard,
            stringResource(R.string.add_manual_title),
            subtitle = stringResource(R.string.add_manual_body),
            onClick = { onChoose(AddMode.MANUAL) },
        )
        SettingsRow(
            Icons.Filled.FileUpload,
            stringResource(R.string.add_import_title),
            subtitle = stringResource(R.string.add_import_body),
            onClick = { onChoose(AddMode.IMPORT) },
        )
    }
}

/** The long-press menu of one account. */
@Composable
fun ItemMenuContent(
    item: VaultItem,
    onEdit: () -> Unit,
    onPin: () -> Unit,
    onTags: () -> Unit,
    onNext: () -> Unit,
    onDelete: () -> Unit,
) {
    val otp = item.otp
    Column(Modifier.navigationBarsPadding().padding(bottom = Space.Lg)) {
        Row(
            Modifier.padding(horizontal = Space.Lg, vertical = Space.Sm),
            horizontalArrangement = Arrangement.spacedBy(Space.Lg),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IssuerAvatar(otp.issuer, otp.label, iconKey = item.icon, size = 44.dp)
            Column {
                Text(otp.issuer.ifEmpty { otp.label }, style = MaterialTheme.typography.titleMedium, maxLines = 1)
                if (otp.issuer.isNotEmpty()) {
                    Text(
                        otp.label,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                    )
                }
            }
        }
        if (otp.type == OtpType.HOTP) SettingsRow(Icons.Filled.Refresh, stringResource(R.string.next_code), onClick = onNext)
        SettingsRow(Icons.Filled.Edit, stringResource(R.string.menu_edit), onClick = onEdit)
        SettingsRow(Icons.Filled.PushPin, stringResource(if (item.favorite) R.string.menu_unpin else R.string.menu_pin), onClick = onPin)
        SettingsRow(Icons.AutoMirrored.Filled.Label, stringResource(R.string.menu_tags), onClick = onTags)
        SettingsRow(Icons.Filled.Delete, stringResource(R.string.delete), onClick = onDelete, danger = true)
    }
}

@OptIn(ExperimentalLayoutApi::class, ExperimentalFoundationApi::class)
@Composable
private fun TagsDialog(
    item: VaultItem,
    existing: List<String>,
    onDismiss: () -> Unit,
    onSave: (List<String>) -> Unit,
) {
    var text by remember(item.id) { mutableStateOf(item.otp.tags.joinToString(", ")) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.menu_tags)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Space.Md)) {
                OutlinedTextField(
                    text,
                    { text = it },
                    label = { Text(stringResource(R.string.tags)) },
                    modifier = Modifier.fillMaxWidth(),
                )
                if (existing.isNotEmpty()) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                        val current = parseTags(text)
                        existing.forEach { tag ->
                            val on = current.any { it.equals(tag, ignoreCase = true) }
                            FilterChip(
                                selected = on,
                                onClick = {
                                    val next = if (on) current.filterNot { it.equals(tag, ignoreCase = true) } else current + tag
                                    text = next.joinToString(", ")
                                },
                                label = { Text(tag) },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onSave(parseTags(text)) }) { Text(stringResource(R.string.save)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun DeleteDialog(
    item: VaultItem,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.delete_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Space.Sm)) {
                Text(item.otp.issuer.ifEmpty { item.otp.label }, style = MaterialTheme.typography.titleSmall)
                Text(stringResource(R.string.delete_body))
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
