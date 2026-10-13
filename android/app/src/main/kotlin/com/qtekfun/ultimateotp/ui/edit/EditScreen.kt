// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.edit

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.ui.codes.parseTags
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.components.SettingsGroup
import com.qtekfun.ultimateotp.ui.components.SettingsSwitchRow
import com.qtekfun.ultimateotp.ui.theme.Space
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class EditViewModel
    @Inject
    constructor(
        private val vault: VaultRepository,
    ) : ViewModel() {
        val items: StateFlow<List<VaultItem>> = vault.items.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

        fun save(
            item: VaultItem,
            done: () -> Unit,
        ) = viewModelScope.launch {
            vault.update(item)
            done()
        }

        fun delete(
            item: VaultItem,
            done: () -> Unit,
        ) = viewModelScope.launch {
            vault.delete(item.id)
            done()
        }
    }

@Composable
fun EditScreen(
    id: String,
    onDone: () -> Unit,
    model: EditViewModel = hiltViewModel(),
) {
    val items by model.items.collectAsState()
    val item = items.firstOrNull { it.id.toString() == id } ?: return
    EditContent(
        item = item,
        onSave = { model.save(it, onDone) },
        onDelete = { model.delete(item, onDone) },
        onBack = onDone,
    )
}

/** The edit screen, stateless. The secret and the code parameters are shown, never edited. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun EditContent(
    item: VaultItem,
    onSave: (VaultItem) -> Unit,
    onDelete: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var issuer by rememberSaveable(item.id) { mutableStateOf(item.otp.issuer) }
    var label by rememberSaveable(item.id) { mutableStateOf(item.otp.label) }
    var tags by rememberSaveable(item.id) { mutableStateOf(item.otp.tags.joinToString(", ")) }
    var notes by rememberSaveable(item.id) { mutableStateOf(item.notes) }
    var favorite by rememberSaveable(item.id) { mutableStateOf(item.favorite) }
    var confirmDelete by rememberSaveable { mutableStateOf(false) }
    val digitsLabel = pluralStringResource(R.plurals.digits_count, item.otp.digits, item.otp.digits)
    FlowScaffold(title = stringResource(R.string.edit_account), onBack = onBack, modifier = modifier) {
        Row(horizontalArrangement = Arrangement.spacedBy(Space.Lg), verticalAlignment = Alignment.CenterVertically) {
            IssuerAvatar(issuer, label, iconKey = item.icon, size = 64.dp)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.Sm), verticalArrangement = Arrangement.spacedBy(Space.Xs)) {
                AssistChip(onClick = {}, label = { Text(item.otp.type.name) })
                AssistChip(onClick = {}, label = { Text(digitsLabel) })
                AssistChip(onClick = {}, label = { Text(item.otp.algorithm.name) })
            }
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
            tags,
            { tags = it },
            label = { Text(stringResource(R.string.tags)) },
            singleLine = true,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            notes,
            { notes = it },
            label = { Text(stringResource(R.string.notes)) },
            minLines = 3,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        )
        SettingsGroup(title = stringResource(R.string.edit_options)) {
            SettingsSwitchRow(
                icon = Icons.Filled.PushPin,
                title = stringResource(R.string.pin_on_top),
                subtitle = stringResource(R.string.pin_on_top_body),
                checked = favorite,
                onCheckedChange = { favorite = it },
            )
        }
        Button(
            onClick = {
                onSave(
                    item.copy(
                        otp = item.otp.copy(issuer = issuer.trim(), label = label.trim(), tags = parseTags(tags)),
                        notes = notes,
                        favorite = favorite,
                    ),
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.save)) }
        OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error)
            Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(start = Space.Sm))
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.delete_title)) },
            text = { Text(stringResource(R.string.delete_body)) },
            confirmButton = {
                TextButton(
                    onClick = onDelete,
                ) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}
