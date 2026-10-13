// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.otp.OtpGenerator
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.util.SecureClipboard
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

@HiltViewModel
class CodesViewModel
    @Inject
    constructor(
        private val vault: VaultRepository,
        private val clipboard: SecureClipboard,
    ) : ViewModel() {
        val items: StateFlow<List<VaultItem>> = vault.items.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), emptyList())

        fun copy(code: String) = clipboard.copy(code)

        /** HOTP: advance the counter (stored first), then copy the new code. */
        fun nextHotp(id: UUID) =
            viewModelScope.launch {
                val item = vault.nextHotpCounter(id) ?: return@launch
                clipboard.copy(OtpGenerator.code(item.otp, System.currentTimeMillis()))
            }

        private companion object {
            const val STOP_MS = 5_000L
        }
    }

/** Groups a code for reading: `123 456`, `1234 5678`. */
fun formatCode(code: String): String = if (code.length < GROUP_MIN) code else code.chunked((code.length + 1) / 2).joinToString(" ")

private const val GROUP_MIN = 6
private const val TICK_MS = 1_000L

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CodesScreen(
    onAdd: () -> Unit,
    onEdit: (UUID) -> Unit,
    onSettings: () -> Unit,
    model: CodesViewModel = hiltViewModel(),
) {
    val items by model.items.collectAsState()
    var query by remember { mutableStateOf("") }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val copied = stringResource(R.string.code_copied)
    val now by produceState(System.currentTimeMillis()) {
        while (true) {
            value = System.currentTimeMillis()
            delay(TICK_MS - value % TICK_MS)
        }
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    IconButton(onClick = onSettings) { Icon(Icons.Default.Settings, stringResource(R.string.settings)) }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAdd) { Icon(Icons.Default.Add, stringResource(R.string.add_account)) }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.search)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
            val shown =
                items.filter {
                    query.isBlank() || it.otp.issuer.contains(query, true) || it.otp.label.contains(query, true) ||
                        it.otp.tags.any { t -> t.contains(query, true) }
                }
            if (items.isEmpty()) {
                Text(stringResource(R.string.empty_vault), modifier = Modifier.padding(24.dp))
            }
            LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(shown, key = { it.id }) { item ->
                    CodeCard(
                        item = item,
                        now = now,
                        onCopy = { code ->
                            model.copy(code)
                            scope.launch { snackbar.showSnackbar(copied) }
                        },
                        onNext = { model.nextHotp(item.id) },
                        onEdit = { onEdit(item.id) },
                    )
                }
            }
        }
    }
}

@Composable
private fun CodeCard(
    item: VaultItem,
    now: Long,
    onCopy: (String) -> Unit,
    onNext: () -> Unit,
    onEdit: () -> Unit,
) {
    val otp = item.otp
    val code = OtpGenerator.code(otp, now)
    Card(modifier = Modifier.fillMaxWidth().combinedClickable(onClick = { onCopy(code) }, onLongClick = onEdit)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (item.favorite) Icon(Icons.Default.Star, null, Modifier.size(16.dp))
                    Text(otp.issuer.ifEmpty { otp.label }, style = MaterialTheme.typography.titleMedium)
                }
                if (otp.issuer.isNotEmpty()) Text(otp.label, style = MaterialTheme.typography.bodySmall)
                Text(formatCode(code), style = MaterialTheme.typography.headlineMedium, fontFamily = FontFamily.Monospace)
            }
            if (otp.type == OtpType.HOTP) {
                IconButton(onClick = onNext) { Icon(Icons.Default.Refresh, stringResource(R.string.next_code)) }
            } else {
                val remaining = OtpGenerator.millisUntilNextStep(now, otp.period)
                CircularProgressIndicator(
                    progress = { remaining / (otp.period * TICK_MS.toFloat()) },
                    modifier = Modifier.size(28.dp),
                )
            }
        }
    }
}
