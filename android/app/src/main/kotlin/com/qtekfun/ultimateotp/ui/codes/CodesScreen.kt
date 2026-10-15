// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.auth.GateResult
import com.qtekfun.ultimateotp.core.otp.OtpGenerator
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.core.sync.model.ItemOrder
import com.qtekfun.ultimateotp.core.sync.model.SortMode
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.features.EntryOrderViewModel
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.sync.SyncStatus
import com.qtekfun.ultimateotp.ui.components.LocalNetworkAccessPrompt
import com.qtekfun.ultimateotp.ui.components.currentWidthClass
import com.qtekfun.ultimateotp.util.AppSettings
import com.qtekfun.ultimateotp.util.SecureClipboard
import com.qtekfun.ultimateotp.util.Settings
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
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
        private val appSettings: AppSettings,
        private val sync: SyncController,
        private val gate: AuthGate,
    ) : ViewModel() {
        val settings: StateFlow<Settings> = appSettings.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())

        /** The entries in the order of the "Sort by" setting; the manual order is what the vault keeps. */
        val items: StateFlow<List<VaultItem>> =
            combine(vault.items, appSettings.settings.map { it.sortMode }.distinctUntilChanged()) { all, mode ->
                ItemOrder.sorted(all, mode)
            }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), emptyList())
        val syncIndicator: StateFlow<SyncIndicator> =
            sync.status.map(::indicator).stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), SyncIndicator.LOCAL)

        fun copy(code: String) = clipboard.copy(code)

        /** HOTP: advance the counter (stored first), then copy the new code. */
        fun nextHotp(id: UUID) =
            viewModelScope.launch {
                val item = (gate.attempt { vault.nextHotpCounter(id) } as? GateResult.Done)?.value ?: return@launch
                clipboard.copy(OtpGenerator.code(item.otp, System.currentTimeMillis()))
            }

        /** After the local-network permission was granted: try again at once. */
        fun retrySync() = sync.syncNow()

        fun setGrid(grid: Boolean) = viewModelScope.launch { appSettings.update { it.copy(gridLayout = grid) } }

        fun togglePin(item: VaultItem) = viewModelScope.launch { vault.update(item.copy(favorite = !item.favorite)) }

        fun setTags(
            item: VaultItem,
            tags: List<String>,
        ) = viewModelScope.launch { vault.update(item.copy(otp = item.otp.copy(tags = tags))) }

        /** The app lock: forgets the keys now; the lock screen follows. */
        fun lock() = vault.lock()

        fun syncNow() = sync.syncNow()

        private companion object {
            const val STOP_MS = 5_000L

            fun indicator(status: SyncStatus): SyncIndicator =
                when {
                    status.account == null -> SyncIndicator.LOCAL
                    status.running -> SyncIndicator.SYNCING
                    status.offline -> SyncIndicator.OFFLINE
                    status.last is SyncResult.Rejected || status.last == SyncResult.Revoked -> SyncIndicator.PROBLEM
                    else -> SyncIndicator.SYNCED
                }
        }
    }

private const val TICK_MS = 1_000L
private const val COPIED_MS = 1_600L

/** The main screen: the stateful part. [CodesContent] draws it and is what the screenshots render. */
@Composable
fun CodesScreen(
    onAdd: (AddMode) -> Unit,
    onEdit: (UUID) -> Unit,
    onSettings: () -> Unit,
    onSync: () -> Unit,
    onTrash: () -> Unit,
    model: CodesViewModel = hiltViewModel(),
    order: EntryOrderViewModel = hiltViewModel(),
) {
    val items by model.items.collectAsState()
    val settings by model.settings.collectAsState()
    val sync by model.syncIndicator.collectAsState()
    LocalNetworkAccessPrompt(active = sync == SyncIndicator.OFFLINE, onGranted = model::retrySync)
    var query by rememberSaveable { mutableStateOf("") }
    var searching by rememberSaveable { mutableStateOf(false) }
    var tag by rememberSaveable { mutableStateOf<String?>(null) }
    var addSheet by rememberSaveable { mutableStateOf(false) }
    var menuId by rememberSaveable { mutableStateOf<String?>(null) }
    var tagsId by rememberSaveable { mutableStateOf<String?>(null) }
    var deleteId by rememberSaveable { mutableStateOf<String?>(null) }
    var selectedId by rememberSaveable { mutableStateOf<String?>(null) }
    var copiedId by remember { mutableStateOf<UUID?>(null) }
    var revealedId by remember { mutableStateOf<UUID?>(null) }
    val haptics = LocalHapticFeedback.current
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val trashedText = stringResource(R.string.moved_to_trash)
    val undoText = stringResource(R.string.undo)
    val now by produceState(System.currentTimeMillis()) {
        while (true) {
            value = System.currentTimeMillis()
            delay(TICK_MS - value % TICK_MS)
        }
    }
    LaunchedEffect(copiedId) {
        if (copiedId != null) {
            delay(COPIED_MS)
            copiedId = null
        }
    }

    fun find(id: String?): VaultItem? = id?.let { s -> items.firstOrNull { it.id.toString() == s } }
    val ui =
        CodesUi(
            query = query,
            searching = searching,
            tag = tag,
            grid = settings.gridLayout,
            manualOrder = settings.sortMode == SortMode.MANUAL,
            addSheet = addSheet,
            menuId = find(menuId)?.id,
            tagsId = find(tagsId)?.id,
            deleteId = find(deleteId)?.id,
            selectedId = find(selectedId)?.id,
            copiedId = copiedId,
            hideCodes = settings.hideCodes,
            revealedId = revealedId,
            sync = sync,
        )
    val actions =
        remember(model, order, onAdd, onEdit, onSettings, onSync, onTrash, trashedText, undoText) {
            CodesActions(
                onQuery = { query = it },
                onSearching = {
                    searching = it
                    if (!it) query = ""
                },
                onTag = { tag = it },
                onToggleGrid = { model.setGrid(!model.settings.value.gridLayout) },
                onAddSheet = { addSheet = it },
                onAdd = {
                    addSheet = false
                    onAdd(it)
                },
                onMenu = {
                    menuId = it?.toString()
                    if (it != null) haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                },
                onTagsDialog = { tagsId = it?.toString() },
                onDeleteDialog = { deleteId = it?.toString() },
                onSelect = { selectedId = it.toString() },
                onCopy = { item, code ->
                    model.copy(code)
                    copiedId = item.id
                    selectedId = item.id.toString()
                    haptics.performHapticFeedback(HapticFeedbackType.Confirm)
                },
                onNext = {
                    model.nextHotp(it.id)
                    copiedId = it.id
                    haptics.performHapticFeedback(HapticFeedbackType.Confirm)
                },
                onEdit = {
                    menuId = null
                    onEdit(it)
                },
                onTogglePin = {
                    menuId = null
                    model.togglePin(it)
                },
                onSetTags = { item, tags ->
                    tagsId = null
                    model.setTags(item, tags)
                },
                onDelete = {
                    deleteId = null
                    menuId = null
                    order.delete(it.id)
                    scope.launch {
                        snackbar.currentSnackbarData?.dismiss()
                        val result = snackbar.showSnackbar(trashedText, actionLabel = undoText, duration = SnackbarDuration.Long)
                        if (result == SnackbarResult.ActionPerformed) order.undoDelete(it.id)
                    }
                },
                onTrash = onTrash,
                onReorder = { from, to ->
                    val shown = order.entries.value
                    val a = shown.indexOfFirst { it.id == from }
                    val b = shown.indexOfFirst { it.id == to }
                    if (a >= 0 && b >= 0) order.move(a, b)
                },
                onSettings = onSettings,
                onSync = onSync,
                onLock = model::lock,
                onReveal = { revealedId = it },
            )
        }
    CodesContent(items = items, now = now, ui = ui, on = actions, widthClass = currentWidthClass(), snackbar = snackbar)
}
