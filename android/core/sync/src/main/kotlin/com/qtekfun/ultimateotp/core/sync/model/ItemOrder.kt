// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

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
                        { it.otp.issuer.lowercase() },
                        { it.otp.label.lowercase() },
                        { it.id },
                    )
                }
            }
        }

    fun sorted(items: Collection<VaultItem>): List<VaultItem> = items.sortedWith(COMPARATOR)

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
