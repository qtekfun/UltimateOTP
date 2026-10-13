// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * The list actions the redesigned codes screen needs, with no UI of their own: the entries in
 * display order, `move(from, to)` for drag and drop, and delete with undo (the trash).
 * Indexes refer to [entries] as shown. Persisted order keys sync and merge by themselves.
 */
@HiltViewModel
class EntryOrderViewModel
    @Inject
    constructor(
        private val vault: VaultRepository,
    ) : ViewModel() {
        val entries: StateFlow<List<VaultItem>> =
            vault.items.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), emptyList())

        /** Moves the entry at [from] to position [to]. Out-of-range indexes are ignored. */
        fun move(
            from: Int,
            to: Int,
        ) {
            val size = entries.value.size
            if (from !in 0 until size || to !in 0 until size || from == to) return
            viewModelScope.launch { vault.move(from, to) }
        }

        /** Moves an entry to the trash; show "Undo" and call [undoDelete] with the same id. */
        fun delete(id: UUID) {
            viewModelScope.launch { vault.trash(id) }
        }

        fun undoDelete(id: UUID) {
            viewModelScope.launch { vault.restore(id) }
        }

        private companion object {
            const val STOP_MS = 5_000L
        }
    }
