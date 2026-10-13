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
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import com.qtekfun.ultimateotp.ui.theme.Space
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
@Composable
fun AutofillAssociationsScreen(
    onBack: () -> Unit,
    model: AutofillAssociationsViewModel = hiltViewModel(),
) {
    val entries by model.entries.collectAsState()
    FlowScaffold(title = stringResource(R.string.autofill_associations), onBack = onBack) {
        Callout(stringResource(R.string.autofill_associations_help))
        for (item in entries) {
            // Kept across a fold or rotation, never written to saved state.
            var text by rememberRetainedText("associations-${item.id}", item.autofill.joinToString("\n"))
            Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
                Column(Modifier.padding(Space.Md), verticalArrangement = Arrangement.spacedBy(Space.Sm)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
                        IssuerAvatar(item.otp.issuer, item.otp.label, iconKey = item.icon, size = 40.dp)
                        OutlinedTextField(
                            value = text,
                            onValueChange = { text = it },
                            label = { Text(listOf(item.otp.issuer, item.otp.label).filter { it.isNotBlank() }.joinToString(" · ")) },
                            modifier = Modifier.weight(1f),
                        )
                    }
                    TextButton(onClick = { model.save(item.id, text) }, modifier = Modifier.align(Alignment.End)) {
                        Text(stringResource(R.string.autofill_save))
                    }
                }
            }
        }
    }
}
