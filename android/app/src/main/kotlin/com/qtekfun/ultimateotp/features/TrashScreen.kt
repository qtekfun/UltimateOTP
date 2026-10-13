// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.sync.history.HistoryRecovery
import com.qtekfun.ultimateotp.core.sync.history.RecoverableEntry
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** Local trash (30 days) and, behind a button, entries the server still holds after a permanent delete. */
@HiltViewModel
class TrashViewModel
    @Inject
    constructor(
        private val vault: VaultRepository,
        private val history: HistoryRecovery,
        private val diagnostics: DiagnosticsLog,
    ) : ViewModel() {
        val trashed: StateFlow<List<VaultItem>> =
            vault.trashed.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), emptyList())

        /** Null until loaded; empty list = nothing recoverable. */
        val serverEntries = MutableStateFlow<List<RecoverableEntry>?>(null)

        fun restore(id: UUID) = viewModelScope.launch { vault.restore(id) }

        fun purge(id: UUID) = viewModelScope.launch { vault.purge(id) }

        fun emptyTrash() = viewModelScope.launch { vault.emptyTrash() }

        fun loadServer() =
            viewModelScope.launch {
                serverEntries.value =
                    try {
                        history.deletedEntries()
                    } catch (e: java.io.IOException) {
                        diagnostics.event("history", "server trash unavailable: ${e.javaClass.simpleName}")
                        emptyList()
                    } catch (e: IllegalStateException) {
                        // No account on this device.
                        diagnostics.event("history", "server trash needs an account (${e.javaClass.simpleName})")
                        emptyList()
                    }
            }

        fun restoreFromServer(id: UUID) =
            viewModelScope.launch {
                runCatching { history.restoreDeleted(id) }
                loadServer()
            }

        private companion object {
            const val STOP_MS = 5_000L
        }
    }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(
    onBack: () -> Unit,
    model: TrashViewModel = hiltViewModel(),
) {
    val items by model.trashed.collectAsState()
    val server by model.serverEntries.collectAsState()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.trash)) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                    ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (items.isEmpty()) item { Text(stringResource(R.string.trash_empty)) }
            items(items, key = { it.id }) { item ->
                Column {
                    Text(listOf(item.otp.issuer, item.otp.label).filter { it.isNotBlank() }.joinToString(" · "))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { model.restore(item.id) }) { Text(stringResource(R.string.trash_restore)) }
                        TextButton(onClick = { model.purge(item.id) }) { Text(stringResource(R.string.trash_delete_forever)) }
                    }
                    HorizontalDivider()
                }
            }
            if (items.isNotEmpty()) {
                item {
                    OutlinedButton(
                        onClick = model::emptyTrash,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.trash_empty_all)) }
                }
            }
            item { Text(stringResource(R.string.trash_server_title)) }
            item {
                Button(
                    onClick = model::loadServer,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.trash_server_load)) }
            }
            server?.let { list ->
                if (list.isEmpty()) item { Text(stringResource(R.string.trash_server_none)) }
                items(list, key = { it.item.id }) { entry ->
                    Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                        Text(listOf(entry.item.otp.issuer, entry.item.otp.label).filter { it.isNotBlank() }.joinToString(" · "))
                        TextButton(onClick = { model.restoreFromServer(entry.item.id) }) { Text(stringResource(R.string.trash_restore)) }
                    }
                }
            }
        }
    }
}
