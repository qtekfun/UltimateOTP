// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import java.util.UUID
import javax.inject.Inject

@HiltViewModel
class AutofillAssociationsViewModel
    @Inject
    constructor(
        private val vault: VaultRepository,
    ) : ViewModel() {
        val entries: StateFlow<List<VaultItem>> =
            vault.items.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), emptyList())

        fun save(
            id: UUID,
            text: String,
        ) = viewModelScope.launch { vault.setAutofillAssociations(id, text.split('\n', ',', ' ').filter { it.isNotBlank() }) }

        private companion object {
            const val STOP_MS = 5_000L
        }
    }

/** The apps and sites an entry's code may be offered for: one text field per entry. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AutofillAssociationsScreen(
    onBack: () -> Unit,
    model: AutofillAssociationsViewModel = hiltViewModel(),
) {
    val entries by model.entries.collectAsState()
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.autofill_associations)) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                    ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            item { Text(stringResource(R.string.autofill_associations_help)) }
            items(entries, key = { it.id }) { item ->
                var text by remember(item.id, item.autofill) { mutableStateOf(item.autofill.joinToString("\n")) }
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    OutlinedTextField(
                        value = text,
                        onValueChange = { text = it },
                        label = { Text(listOf(item.otp.issuer, item.otp.label).filter { it.isNotBlank() }.joinToString(" · ")) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    TextButton(onClick = { model.save(item.id, text) }) { Text(stringResource(R.string.autofill_save)) }
                }
            }
        }
    }
}
