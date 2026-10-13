// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
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
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.theme.Space
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

@Composable
fun TrashScreen(
    onBack: () -> Unit,
    model: TrashViewModel = hiltViewModel(),
) {
    val items by model.trashed.collectAsState()
    val server by model.serverEntries.collectAsState()
    TrashContent(
        items = items,
        server = server,
        onBack = onBack,
        onRestore = { model.restore(it) },
        onPurge = { model.purge(it) },
        onEmpty = model::emptyTrash,
        onLoadServer = model::loadServer,
        onRestoreFromServer = { model.restoreFromServer(it) },
    )
}

/** The trash, stateless: removed entries, and the entries the server still holds once asked. */
@Composable
fun TrashContent(
    items: List<VaultItem>,
    server: List<RecoverableEntry>?,
    onBack: () -> Unit,
    onRestore: (UUID) -> Unit,
    onPurge: (UUID) -> Unit,
    onEmpty: () -> Unit,
    onLoadServer: () -> Unit,
    onRestoreFromServer: (UUID) -> Unit,
) {
    FlowScaffold(title = stringResource(R.string.trash), onBack = onBack) {
        if (items.isEmpty()) Callout(stringResource(R.string.trash_empty))
        for (item in items) {
            TrashRow(item.otp.issuer, item.otp.label, item.icon) {
                TextButton(onClick = { onRestore(item.id) }) {
                    Icon(Icons.Filled.Restore, contentDescription = null)
                    Text(stringResource(R.string.trash_restore), Modifier.padding(start = Space.Sm))
                }
                TextButton(onClick = { onPurge(item.id) }) {
                    Icon(Icons.Filled.DeleteForever, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                    Text(
                        stringResource(R.string.trash_delete_forever),
                        Modifier.padding(start = Space.Sm),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
        if (items.isNotEmpty()) {
            OutlinedButton(
                onClick = onEmpty,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = MaterialTheme.shapes.large,
            ) { Text(stringResource(R.string.trash_empty_all)) }
        }
        Text(
            stringResource(R.string.trash_server_title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = Space.Md).semantics { heading() },
        )
        FilledTonalButton(
            onClick = onLoadServer,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = MaterialTheme.shapes.large,
        ) { Text(stringResource(R.string.trash_server_load)) }
        server?.let { list ->
            if (list.isEmpty()) Callout(stringResource(R.string.trash_server_none))
            for (entry in list) {
                TrashRow(entry.item.otp.issuer, entry.item.otp.label, entry.item.icon) {
                    TextButton(onClick = { onRestoreFromServer(entry.item.id) }) {
                        Icon(Icons.Filled.Restore, contentDescription = null)
                        Text(stringResource(R.string.trash_restore), Modifier.padding(start = Space.Sm))
                    }
                }
            }
        }
    }
}

/** One removed entry: its logo and name, with the actions below. */
@Composable
private fun TrashRow(
    issuer: String,
    label: String,
    icon: String?,
    actions: @Composable RowScope.() -> Unit,
) {
    Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
        Column(Modifier.padding(Space.Md), verticalArrangement = Arrangement.spacedBy(Space.Xs)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
                IssuerAvatar(issuer, label, iconKey = icon, size = 40.dp)
                Text(
                    listOf(issuer, label).filter { it.isNotBlank() }.joinToString(" · "),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(Space.Sm), content = actions)
        }
    }
}
