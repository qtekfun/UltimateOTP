// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

/** How the list is ordered on this device (a local preference, like Ente's sort menu). */
enum class SortMode {
    /** Pinned first, then by provider (the account name when the provider is empty). The default. */
    ALPHABETICAL,

    /** The hand-made order of [ItemOrder.COMPARATOR]: dragged entries first, the rest alphabetical. */
    MANUAL,

    /** Pinned first, then the most recently added. */
    NEWEST,

    /** Pinned first, then the oldest first. */
    OLDEST,
}

/**
 * The display order of the entries and the drag-and-drop operation on it.
 *
 * Entries with a manual [VaultItem.order] come first, by key (ties by id, so every device shows
 * the same list), then entries never placed by hand: favorites, issuer, label, id.
 */
object ItemOrder {
    val COMPARATOR: Comparator<VaultItem> =
        Comparator { a, b ->
            when {
                a.order != null && b.order != null -> {
                    compareValuesBy(a, b, { it.order }, { it.id })
                }

                a.order != null -> {
                    -1
                }

                b.order != null -> {
                    1
                }

                else -> {
                    compareValuesBy(
                        a,
                        b,
                        { !it.favorite },
                        { nameKey(it) },
                        { it.otp.label.lowercase() },
                        { it.id },
                    )
                }
            }
        }

    /** What the entry is called in the list: the provider, or the account when there is none. */
    fun nameKey(item: VaultItem): String =
        item.otp.issuer
            .ifBlank { item.otp.label }
            .lowercase()

    private val ALPHABETICAL: Comparator<VaultItem> =
        compareBy<VaultItem>({ !it.favorite }, { nameKey(it) }, { it.otp.label.lowercase() }, { it.id })

    private val NEWEST: Comparator<VaultItem> =
        compareBy<VaultItem> { !it.favorite }.thenByDescending { it.created }.thenBy { nameKey(it) }.thenBy { it.id }

    private val OLDEST: Comparator<VaultItem> =
        compareBy<VaultItem>({ !it.favorite }, { it.created }, { nameKey(it) }, { it.id })

    /** The manual order (what is stored and synced); see [sorted] with a [SortMode] for the others. */
    fun sorted(items: Collection<VaultItem>): List<VaultItem> = items.sortedWith(COMPARATOR)

    fun sorted(
        items: Collection<VaultItem>,
        mode: SortMode,
    ): List<VaultItem> =
        items.sortedWith(
            when (mode) {
                SortMode.ALPHABETICAL -> ALPHABETICAL
                SortMode.MANUAL -> COMPARATOR
                SortMode.NEWEST -> NEWEST
                SortMode.OLDEST -> OLDEST
            },
        )

    /**
     * Moves the entry at [from] to index [to] of [sorted] (the displayed list, after the move it
     * sits at [to]) and returns only the entries whose position changed, with new keys and
     * `orderChanged = now`. Usually that is one entry; when the neighbours have no usable keys
     * (never placed, or equal) the whole list is keyed again.
     */
    fun move(
        sorted: List<VaultItem>,
        from: Int,
        to: Int,
        now: Long,
    ): List<VaultItem> {
        require(from in sorted.indices && to in sorted.indices) { "index out of range" }
        if (from == to) return emptyList()
        val target = sorted.toMutableList()
        val moved = target.removeAt(from)
        target.add(to, moved)
        val before = target.getOrNull(to - 1)?.order
        val after = target.getOrNull(to + 1)?.order
        // An unkeyed neighbour after the target means only unkeyed entries follow, which sort
        // after every key anyway, so "no upper bound" is right. An unkeyed one before it is not.
        val usable = (to == 0 || before != null) && (before == null || after == null || before < after)
        val keys = if (usable) null else OrderKeys.initial(target.size)
        return if (keys == null) {
            listOf(moved.copy(order = OrderKeys.between(before, after), orderChanged = now))
        } else {
            target.mapIndexedNotNull { i, item -> if (item.order == keys[i]) null else item.copy(order = keys[i], orderChanged = now) }
        }
    }
}
