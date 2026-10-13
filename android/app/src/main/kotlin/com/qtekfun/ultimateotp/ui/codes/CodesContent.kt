// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyGridScope
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.ViewAgenda
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.ui.components.UotpLogo
import com.qtekfun.ultimateotp.ui.components.WidthClass
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.ui.theme.status

private val ListMinCell = 340.dp
private val GridMinCell = 168.dp
private val FabClearance = 96.dp

/**
 * The codes screen, stateless: the accounts, the clock [now] and what is open ([ui]) in; user intents out.
 * Compact windows get one list or grid; medium ones several columns; expanded ones a list with a
 * detail pane for the selected account.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CodesContent(
    items: List<VaultItem>,
    now: Long,
    ui: CodesUi,
    on: CodesActions,
    widthClass: WidthClass,
    modifier: Modifier = Modifier,
) {
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val gridState = rememberLazyGridState()
    val fabExpanded by remember { derivedStateOf { gridState.firstVisibleItemIndex == 0 } }
    Scaffold(
        modifier = modifier.nestedScroll(scroll.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            if (ui.searching) {
                SearchTopBar(ui.query, on.onQuery) { on.onSearching(false) }
            } else {
                CodesTopBar(items.size, ui, on, scroll)
            }
        },
        floatingActionButton = {
            if (items.isNotEmpty()) {
                ExtendedFloatingActionButton(
                    onClick = { on.onAddSheet(true) },
                    expanded = fabExpanded,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.add_account)) },
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
        },
    ) { padding ->
        val filtered = filterItems(items, ui.query, ui.tag)
        when {
            items.isEmpty() -> {
                EmptyCodes(
                    onAdd = { on.onAddSheet(true) },
                    onImport = { on.onAdd(AddMode.IMPORT) },
                    Modifier.padding(padding),
                )
            }

            widthClass == WidthClass.EXPANDED -> {
                TwoPane(items, filtered, now, ui, on, padding, gridState)
            }

            else -> {
                CodesGrid(items, filtered, now, ui, on, padding, gridState, widthClass, Modifier.fillMaxSize())
            }
        }
    }
    CodesSheets(items, ui, on)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CodesTopBar(
    count: Int,
    ui: CodesUi,
    on: CodesActions,
    scroll: androidx.compose.material3.TopAppBarScrollBehavior,
) {
    LargeTopAppBar(
        title = {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
                UotpLogo(size = 32.dp)
                Text(stringResource(R.string.app_name), maxLines = 1)
            }
        },
        actions = {
            if (count > 0) {
                IconButton(onClick = { on.onSearching(true) }) { Icon(Icons.Filled.Search, stringResource(R.string.search)) }
            }
            SyncStatusButton(ui.sync, on.onSync)
            IconButton(onClick = on.onLock) { Icon(Icons.Filled.Lock, stringResource(R.string.lock_now)) }
            OverflowMenu(on)
        },
        scrollBehavior = scroll,
        colors =
            TopAppBarDefaults.topAppBarColors(
                containerColor = MaterialTheme.colorScheme.background,
                scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
            ),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun OverflowMenu(on: CodesActions) {
    var open by remember { mutableStateOf(false) }
    IconButton(onClick = { open = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.more_actions)) }
    DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
        DropdownMenuItem(
            text = { Text(stringResource(R.string.settings)) },
            leadingIcon = { Icon(Icons.Filled.Settings, contentDescription = null) },
            onClick = {
                open = false
                on.onSettings()
            },
        )
        DropdownMenuItem(
            text = { Text(stringResource(R.string.trash)) },
            leadingIcon = { Icon(Icons.Filled.Delete, contentDescription = null) },
            onClick = {
                open = false
                on.onTrash()
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SearchTopBar(
    query: String,
    onQuery: (String) -> Unit,
    onClose: () -> Unit,
) {
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    TopAppBar(
        navigationIcon = {
            IconButton(
                onClick = onClose,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.close_search)) }
        },
        title = {
            TextField(
                value = query,
                onValueChange = onQuery,
                placeholder = { Text(stringResource(R.string.search_hint)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(),
                colors =
                    TextFieldDefaults.colors(
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = Color.Transparent,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                    ),
                modifier = Modifier.fillMaxWidth().focusRequester(focus),
            )
        },
        actions = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQuery("") }) { Icon(Icons.Filled.Close, stringResource(R.string.clear_search)) }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    )
}

/** A discreet icon for the sync state; it opens the sync screen and says the state in words for TalkBack. */
@Composable
private fun SyncStatusButton(
    state: SyncIndicator,
    onClick: () -> Unit,
) {
    val (icon, text) = syncVisual(state)
    val tint =
        when (state) {
            SyncIndicator.SYNCED -> MaterialTheme.status.success
            SyncIndicator.PROBLEM -> MaterialTheme.colorScheme.error
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        }
    val spin =
        if (state == SyncIndicator.SYNCING) {
            rememberInfiniteTransition(label = "sync")
                .animateFloat(
                    0f,
                    360f,
                    infiniteRepeatable(tween(1_400, easing = LinearEasing), RepeatMode.Restart),
                    label = "spin",
                ).value
        } else {
            0f
        }
    IconButton(onClick = onClick) {
        Icon(icon, contentDescription = text, tint = tint, modifier = Modifier.rotate(-spin))
    }
}

@Composable
private fun syncVisual(state: SyncIndicator): Pair<ImageVector, String> =
    when (state) {
        SyncIndicator.LOCAL -> Icons.Filled.PhoneAndroid to stringResource(R.string.sync_state_local)
        SyncIndicator.SYNCING -> Icons.Filled.Sync to stringResource(R.string.sync_state_syncing)
        SyncIndicator.SYNCED -> Icons.Filled.CloudDone to stringResource(R.string.sync_state_synced)
        SyncIndicator.OFFLINE -> Icons.Filled.CloudOff to stringResource(R.string.sync_state_offline)
        SyncIndicator.PROBLEM -> Icons.Filled.ErrorOutline to stringResource(R.string.sync_state_problem)
    }

@Composable
private fun TwoPane(
    items: List<VaultItem>,
    filtered: List<VaultItem>,
    now: Long,
    ui: CodesUi,
    on: CodesActions,
    padding: PaddingValues,
    gridState: androidx.compose.foundation.lazy.grid.LazyGridState,
) {
    val selected = items.firstOrNull { it.id == ui.selectedId } ?: filtered.firstOrNull() ?: items.first()
    Row(Modifier.fillMaxSize()) {
        CodesGrid(
            items,
            filtered,
            now,
            ui.copy(selectedId = selected.id),
            on,
            padding.withoutEnd(),
            gridState,
            WidthClass.COMPACT,
            Modifier.weight(0.44f).fillMaxHeight(),
        )
        VerticalDivider(Modifier.padding(top = padding.calculateTopPadding()), color = MaterialTheme.colorScheme.outlineVariant)
        Box(Modifier.weight(0.56f).fillMaxHeight().padding(top = padding.calculateTopPadding())) {
            CodeDetail(
                item = selected,
                now = now,
                copied = ui.copiedId == selected.id,
                on = on,
                modifier = Modifier.fillMaxSize(),
            )
        }
    }
}

@Composable
private fun PaddingValues.withoutEnd(): PaddingValues {
    val dir = LocalLayoutDirection.current
    return PaddingValues(
        start = calculateStartPadding(dir),
        top = calculateTopPadding(),
        end = 0.dp,
        bottom = calculateBottomPadding(),
    )
}

@Composable
private fun CodesGrid(
    items: List<VaultItem>,
    filtered: List<VaultItem>,
    now: Long,
    ui: CodesUi,
    on: CodesActions,
    padding: PaddingValues,
    state: androidx.compose.foundation.lazy.grid.LazyGridState,
    widthClass: WidthClass,
    modifier: Modifier,
) {
    val dir = LocalLayoutDirection.current
    val columns =
        when {
            ui.grid -> GridCells.Adaptive(GridMinCell)
            widthClass == WidthClass.COMPACT -> GridCells.Fixed(1)
            else -> GridCells.Adaptive(ListMinCell)
        }
    val tags = remember(items) { allTags(items) }
    val filtering = ui.query.isNotBlank() || ui.tag != null
    val pinnedTitle = stringResource(R.string.section_pinned)
    val allTitle = stringResource(R.string.section_all)
    val pinned = if (filtering) emptyList() else filtered.filter { it.favorite }
    val rest = if (filtering) filtered else filtered.filterNot { it.favorite }
    LazyVerticalGrid(
        columns = columns,
        state = state,
        modifier = modifier,
        contentPadding =
            PaddingValues(
                start = padding.calculateStartPadding(dir) + Space.Gutter,
                end = padding.calculateEndPadding(dir) + Space.Gutter,
                top = padding.calculateTopPadding() + Space.Sm,
                bottom = padding.calculateBottomPadding() + FabClearance,
            ),
        horizontalArrangement = Arrangement.spacedBy(Space.Md),
        verticalArrangement = Arrangement.spacedBy(Space.Md),
    ) {
        item(span = { GridItemSpan(maxLineSpan) }, key = "filters") {
            FilterRow(tags, ui.tag, ui.grid, filtered.size, filtering, on)
        }
        if (filtered.isEmpty()) {
            item(span = { GridItemSpan(maxLineSpan) }, key = "empty") { NoResults(Modifier.padding(top = Space.Huge)) }
        }
        if (pinned.isNotEmpty()) {
            header("pinned", pinnedTitle)
            cards(pinned, now, ui, on)
            header("all", allTitle)
        }
        cards(rest, now, ui, on)
    }
}

private fun LazyGridScope.header(
    key: String,
    title: String,
) {
    item(span = { GridItemSpan(maxLineSpan) }, key = "header-$key") {
        Text(
            title,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = Space.Xs, top = Space.Sm).semantics { contentDescription = title },
        )
    }
}

private fun LazyGridScope.cards(
    list: List<VaultItem>,
    now: Long,
    ui: CodesUi,
    on: CodesActions,
) {
    items(list, key = { it.id }) { item ->
        CodeCard(
            item = item,
            now = now,
            compact = ui.grid,
            selected = item.id == ui.selectedId,
            copied = item.id == ui.copiedId,
            hidden = ui.hideCodes && item.id != ui.revealedId,
            onCopy = { code -> if (ui.hideCodes && item.id != ui.revealedId) on.onReveal(item.id) else on.onCopy(item, code) },
            onMenu = { on.onMenu(item.id) },
            onNext = { on.onNext(item) },
        )
    }
}

@Composable
private fun FilterRow(
    tags: List<String>,
    selected: String?,
    grid: Boolean,
    shown: Int,
    filtering: Boolean,
    on: CodesActions,
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        if (tags.isEmpty()) {
            Text(
                pluralStringResource(if (filtering) R.plurals.results_count else R.plurals.accounts_count, shown, shown),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f).padding(start = Space.Xs),
            )
        } else {
            LazyRow(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                item {
                    FilterChip(
                        selected = selected == null,
                        onClick = { on.onTag(null) },
                        label = { Text(stringResource(R.string.filter_all)) },
                    )
                }
                items(tags) { tag ->
                    FilterChip(selected = selected == tag, onClick = {
                        on.onTag(
                            if (selected ==
                                tag
                            ) {
                                null
                            } else {
                                tag
                            },
                        )
                    }, label = { Text(tag) })
                }
            }
        }
        IconButton(onClick = on.onToggleGrid) {
            Icon(
                if (grid) Icons.Filled.ViewAgenda else Icons.Filled.GridView,
                contentDescription = stringResource(if (grid) R.string.layout_list else R.string.layout_grid),
            )
        }
    }
}
