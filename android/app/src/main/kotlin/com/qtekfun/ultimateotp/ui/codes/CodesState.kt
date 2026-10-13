// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import java.util.Locale
import java.util.UUID

/** What the sync indicator on the codes screen says. */
enum class SyncIndicator { LOCAL, SYNCING, SYNCED, OFFLINE, PROBLEM }

/** How the add sheet's choices open the add flow. */
enum class AddMode { SCAN, MANUAL, IMPORT }

/** Everything the codes screen shows besides the accounts themselves; hoisted so tests can set it. */
data class CodesUi(
    val query: String = "",
    val searching: Boolean = false,
    val tag: String? = null,
    val grid: Boolean = false,
    val addSheet: Boolean = false,
    val menuId: UUID? = null,
    val tagsId: UUID? = null,
    val deleteId: UUID? = null,
    val selectedId: UUID? = null,
    val copiedId: UUID? = null,
    /** Setting "hide codes until tapped"; [revealedId] is the account tapped open. */
    val hideCodes: Boolean = false,
    val revealedId: UUID? = null,
    val sync: SyncIndicator = SyncIndicator.LOCAL,
)

/** What the codes screen can ask for; the stateful screen implements them with the view model. */
data class CodesActions(
    val onQuery: (String) -> Unit = {},
    val onSearching: (Boolean) -> Unit = {},
    val onTag: (String?) -> Unit = {},
    val onToggleGrid: () -> Unit = {},
    val onAddSheet: (Boolean) -> Unit = {},
    val onAdd: (AddMode) -> Unit = {},
    val onMenu: (UUID?) -> Unit = {},
    val onTagsDialog: (UUID?) -> Unit = {},
    val onDeleteDialog: (UUID?) -> Unit = {},
    val onSelect: (UUID) -> Unit = {},
    val onCopy: (VaultItem, String) -> Unit = { _, _ -> },
    val onNext: (VaultItem) -> Unit = {},
    val onEdit: (UUID) -> Unit = {},
    val onTogglePin: (VaultItem) -> Unit = {},
    val onSetTags: (VaultItem, List<String>) -> Unit = { _, _ -> },
    val onDelete: (VaultItem) -> Unit = {},
    val onSettings: () -> Unit = {},
    val onSync: () -> Unit = {},
    val onLock: () -> Unit = {},
    /** Opens the trash list. */
    val onTrash: () -> Unit = {},
    /** Drag-and-drop (or accessibility action) reorder: [from] takes the position of [to]. */
    val onReorder: (from: UUID, to: UUID) -> Unit = { _, _ -> },
    val onReveal: (UUID) -> Unit = {},
)

private const val GROUP_MIN = 6

/** Groups a code for reading: `123 456`, `1234 5678`; short (Steam) codes stay whole. */
fun formatCode(code: String): String = if (code.length < GROUP_MIN) code else code.chunked((code.length + 1) / 2).joinToString(" ")

/** Accounts matching the search [query] (issuer, account, tags) and the selected [tag]. */
fun filterItems(
    items: List<VaultItem>,
    query: String,
    tag: String?,
): List<VaultItem> {
    val q = query.trim().lowercase(Locale.ROOT)
    return items.filter { item ->
        val otp = item.otp
        (tag == null || otp.tags.any { it.equals(tag, ignoreCase = true) }) &&
            (
                q.isEmpty() ||
                    otp.issuer.lowercase(Locale.ROOT).contains(q) ||
                    otp.label.lowercase(Locale.ROOT).contains(q) ||
                    otp.tags.any { it.lowercase(Locale.ROOT).contains(q) }
            )
    }
}

/** Every tag in use, sorted, case-insensitively unique. */
fun allTags(items: List<VaultItem>): List<String> =
    items
        .flatMap { it.otp.tags }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinctBy { it.lowercase(Locale.ROOT) }
        .sortedBy { it.lowercase(Locale.ROOT) }

/** Parses a comma separated tag field. */
fun parseTags(text: String): List<String> =
    text
        .split(',')
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinctBy { it.lowercase(Locale.ROOT) }
