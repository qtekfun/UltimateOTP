// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.edit

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditScreen(
    id: String,
    onDone: () -> Unit,
    model: EditViewModel = hiltViewModel(),
) {
    val items by model.items.collectAsState()
    val item = items.firstOrNull { it.id.toString() == id } ?: return
    var issuer by remember(item.id) { mutableStateOf(item.otp.issuer) }
    var label by remember(item.id) { mutableStateOf(item.otp.label) }
    var tags by remember(item.id) { mutableStateOf(item.otp.tags.joinToString(", ")) }
    var notes by remember(item.id) { mutableStateOf(item.notes) }
    var favorite by remember(item.id) { mutableStateOf(item.favorite) }
    var confirmDelete by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.edit_account)) },
                navigationIcon = {
                    IconButton(
                        onClick = onDone,
                    ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                issuer,
                { issuer = it },
                label = { Text(stringResource(R.string.issuer)) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(label, { label = it }, label = { Text(stringResource(R.string.account)) }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(tags, { tags = it }, label = { Text(stringResource(R.string.tags)) }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(notes, { notes = it }, label = { Text(stringResource(R.string.notes)) }, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = favorite, onCheckedChange = { favorite = it })
                Text(stringResource(R.string.favorite))
            }
            Button(onClick = {
                val newTags = tags.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                model.save(
                    item.copy(
                        otp = item.otp.copy(issuer = issuer.trim(), label = label.trim(), tags = newTags),
                        notes = notes,
                        favorite = favorite,
                    ),
                    onDone,
                )
            }) { Text(stringResource(R.string.save)) }
            OutlinedButton(onClick = { confirmDelete = true }) { Text(stringResource(R.string.delete)) }
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.delete_title)) },
            text = { Text(stringResource(R.string.delete_body)) },
            confirmButton = { TextButton(onClick = { model.delete(item, onDone) }) { Text(stringResource(R.string.delete)) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}
