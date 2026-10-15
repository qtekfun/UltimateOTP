// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.settings

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ColorLens
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Contrast
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Gavel
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.ManageAccounts
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.model.SortMode
import com.qtekfun.ultimateotp.ui.components.RowDivider
import com.qtekfun.ultimateotp.ui.components.SettingsGroup
import com.qtekfun.ultimateotp.ui.components.SettingsRow
import com.qtekfun.ultimateotp.ui.components.SettingsSwitchRow
import com.qtekfun.ultimateotp.ui.components.UotpLogo
import com.qtekfun.ultimateotp.ui.components.WidthClass
import com.qtekfun.ultimateotp.ui.components.currentWidthClass
import com.qtekfun.ultimateotp.ui.theme.ContentMaxWidth
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.util.AppLanguage
import com.qtekfun.ultimateotp.util.Settings
import com.qtekfun.ultimateotp.util.ThemeMode

/** What the settings screen can ask for. */
data class SettingsActions(
    val onBack: () -> Unit = {},
    val onSync: () -> Unit = {},
    val onSessions: () -> Unit = {},
    val onLockTimeout: (Int) -> Unit = {},
    val onClipboardClear: (Int) -> Unit = {},
    val onHideCodes: (Boolean) -> Unit = {},
    val onThemeMode: (ThemeMode) -> Unit = {},
    val onAmoled: (Boolean) -> Unit = {},
    val onDynamicColor: (Boolean) -> Unit = {},
    val onGridLayout: (Boolean) -> Unit = {},
    val onSortMode: (SortMode) -> Unit = {},
    val onLanguage: (String) -> Unit = {},
    val onExportEncrypted: () -> Unit = {},
    val onExportPlain: () -> Unit = {},
    val onImport: () -> Unit = {},
    val onTrash: () -> Unit = {},
    val onAccount: () -> Unit = {},
    val onAutofillSettings: () -> Unit = {},
    val onAutofillAssociations: () -> Unit = {},
    val onShareLog: () -> Unit = {},
    val onSaveLog: () -> Unit = {},
    val onClearLog: () -> Unit = {},
)

private const val LOCK_NEVER = -1

/** The stored values of core.support LockTimeout: seconds, -1 for never. */
private val LOCK_CHOICES = listOf(0, 30, 60, 300, LOCK_NEVER)
private val CLIPBOARD_CHOICES = listOf(10, 30, 60, 120)

private enum class Picker { LOCK, CLIPBOARD, THEME, LANGUAGE, SORT }

/** Settings, stateless: grouped sections with icons (Security, Sync, Appearance, Data, About). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsContent(
    settings: Settings,
    statusText: String?,
    version: String,
    language: String,
    actions: SettingsActions,
    modifier: Modifier = Modifier,
    autofillEnabled: Boolean = false,
) {
    var picker by rememberSaveable { mutableStateOf<Picker?>(null) }
    val scroll = TopAppBarDefaults.pinnedScrollBehavior()
    Scaffold(
        modifier = modifier.nestedScroll(scroll.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                navigationIcon = {
                    IconButton(onClick = actions.onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
                scrollBehavior = scroll,
                colors =
                    TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.background,
                        scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                    ),
            )
        },
    ) { padding ->
        // Unfolded (expanded width) the groups fill two columns instead of one 640 dp strip.
        val expanded = currentWidthClass() == WidthClass.EXPANDED
        val first: @Composable () -> Unit = {
            SecurityGroup(settings, actions) { picker = it }
            SyncGroup(actions)
            AutofillGroup(autofillEnabled, actions)
        }
        val second: @Composable () -> Unit = {
            AppearanceGroup(settings, language, actions) { picker = it }
            DataGroup(statusText, actions)
            DiagnosticsGroup(actions)
            AboutGroup(version)
        }
        Box(Modifier.padding(padding), contentAlignment = Alignment.TopCenter) {
            val scrolling =
                Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = Space.Gutter, vertical = Space.Sm)
            if (expanded) {
                Row(
                    scrolling.widthIn(max = ContentMaxWidth * 2),
                    horizontalArrangement = Arrangement.spacedBy(Space.Xl),
                ) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(Space.Xl)) { first() }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(Space.Xl)) { second() }
                }
            } else {
                Column(
                    scrolling.widthIn(max = ContentMaxWidth),
                    verticalArrangement = Arrangement.spacedBy(Space.Xl),
                ) {
                    first()
                    second()
                }
            }
        }
    }
    when (picker) {
        Picker.LOCK -> {
            ChoiceDialog(
                title = stringResource(R.string.lock_timeout_title),
                options = LOCK_CHOICES.map { it to durationText(it) },
                selected = settings.lockTimeoutSeconds,
                onSelect = {
                    actions.onLockTimeout(it)
                    picker = null
                },
                onDismiss = { picker = null },
            )
        }

        Picker.CLIPBOARD -> {
            ChoiceDialog(
                title = stringResource(R.string.clipboard_title),
                options = CLIPBOARD_CHOICES.map { it to durationText(it) },
                selected = settings.clipboardClearSeconds,
                onSelect = {
                    actions.onClipboardClear(it)
                    picker = null
                },
                onDismiss = { picker = null },
            )
        }

        Picker.THEME -> {
            ChoiceDialog(
                title = stringResource(R.string.theme_title),
                options = ThemeMode.entries.map { it to stringResource(themeLabel(it)) },
                selected = settings.themeMode,
                onSelect = {
                    actions.onThemeMode(it)
                    picker = null
                },
                onDismiss = { picker = null },
            )
        }

        Picker.LANGUAGE -> {
            ChoiceDialog(
                title = stringResource(R.string.language_title),
                options = (listOf("") + AppLanguage.SUPPORTED).map { it to stringResource(languageLabel(it)) },
                selected = language,
                onSelect = {
                    actions.onLanguage(it)
                    picker = null
                },
                onDismiss = { picker = null },
            )
        }

        Picker.SORT -> {
            ChoiceDialog(
                title = stringResource(R.string.sort_title),
                options = SortMode.entries.map { it to stringResource(sortLabel(it)) },
                selected = settings.sortMode,
                onSelect = {
                    actions.onSortMode(it)
                    picker = null
                },
                onDismiss = { picker = null },
            )
        }

        null -> {}
    }
}

private fun sortLabel(mode: SortMode): Int =
    when (mode) {
        SortMode.ALPHABETICAL -> R.string.sort_alphabetical
        SortMode.MANUAL -> R.string.sort_manual
        SortMode.NEWEST -> R.string.sort_newest
        SortMode.OLDEST -> R.string.sort_oldest
    }

private fun languageLabel(tag: String): Int =
    when (tag) {
        "en" -> R.string.language_en
        "es" -> R.string.language_es
        else -> R.string.language_system
    }

private fun themeLabel(mode: ThemeMode): Int =
    when (mode) {
        ThemeMode.SYSTEM -> R.string.theme_system
        ThemeMode.LIGHT -> R.string.theme_light
        ThemeMode.DARK -> R.string.theme_dark
    }

@Composable
private fun SecurityGroup(
    settings: Settings,
    actions: SettingsActions,
    open: (Picker) -> Unit,
) {
    SettingsGroup(stringResource(R.string.section_security)) {
        SettingsRow(
            Icons.Filled.Timer,
            stringResource(R.string.lock_timeout_title),
            subtitle = durationText(settings.lockTimeoutSeconds),
            onClick = { open(Picker.LOCK) },
        )
        RowDivider()
        SettingsRow(
            Icons.Filled.ContentPaste,
            stringResource(R.string.clipboard_title),
            subtitle = durationText(settings.clipboardClearSeconds),
            onClick = { open(Picker.CLIPBOARD) },
        )
        RowDivider()
        SettingsSwitchRow(
            Icons.Filled.VisibilityOff,
            stringResource(R.string.hide_codes_title),
            checked = settings.hideCodes,
            onCheckedChange = actions.onHideCodes,
            subtitle = stringResource(R.string.hide_codes_body),
        )
    }
}

@Composable
private fun SyncGroup(actions: SettingsActions) {
    SettingsGroup(stringResource(R.string.section_sync)) {
        SettingsRow(
            Icons.Filled.Cloud,
            stringResource(R.string.sync_open),
            subtitle = stringResource(R.string.sync_open_body),
            onClick = actions.onSync,
        )
        RowDivider()
        SettingsRow(
            Icons.Filled.Devices,
            stringResource(R.string.sessions_title),
            subtitle = stringResource(R.string.sessions_body),
            onClick = actions.onSessions,
        )
        RowDivider()
        SettingsRow(Icons.Filled.ManageAccounts, stringResource(R.string.account_settings), onClick = actions.onAccount)
    }
}

@Composable
private fun AutofillGroup(
    enabled: Boolean,
    actions: SettingsActions,
) {
    SettingsGroup(stringResource(R.string.section_autofill)) {
        SettingsRow(
            Icons.Filled.Password,
            stringResource(R.string.autofill_enable),
            subtitle = stringResource(if (enabled) R.string.autofill_state_on else R.string.autofill_state_off),
            onClick = actions.onAutofillSettings,
        )
        RowDivider()
        SettingsRow(Icons.Filled.Link, stringResource(R.string.autofill_associations), onClick = actions.onAutofillAssociations)
    }
}

@Composable
private fun DiagnosticsGroup(actions: SettingsActions) {
    SettingsGroup(stringResource(R.string.section_diagnostics)) {
        SettingsRow(
            Icons.Filled.BugReport,
            stringResource(R.string.diagnostics_share),
            subtitle = stringResource(R.string.diagnostics_help),
            onClick = actions.onShareLog,
        )
        RowDivider()
        SettingsRow(Icons.Filled.Save, stringResource(R.string.diagnostics_save), onClick = actions.onSaveLog)
        RowDivider()
        SettingsRow(Icons.Filled.DeleteSweep, stringResource(R.string.diagnostics_clear), onClick = actions.onClearLog)
    }
}

@Composable
private fun AppearanceGroup(
    settings: Settings,
    language: String,
    actions: SettingsActions,
    open: (Picker) -> Unit,
) {
    SettingsGroup(stringResource(R.string.section_appearance)) {
        SettingsRow(
            Icons.Filled.Language,
            stringResource(R.string.language_title),
            subtitle = stringResource(languageLabel(language)),
            onClick = { open(Picker.LANGUAGE) },
        )
        RowDivider()
        SettingsRow(
            Icons.Filled.DarkMode,
            stringResource(R.string.theme_title),
            subtitle = stringResource(themeLabel(settings.themeMode)),
            onClick = { open(Picker.THEME) },
        )
        RowDivider()
        SettingsSwitchRow(
            Icons.Filled.Contrast,
            stringResource(R.string.amoled_title),
            checked = settings.amoled,
            onCheckedChange = actions.onAmoled,
            subtitle = stringResource(R.string.amoled_body),
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            RowDivider()
            SettingsSwitchRow(
                Icons.Filled.ColorLens,
                stringResource(R.string.dynamic_color_title),
                checked = settings.dynamicColor,
                onCheckedChange = actions.onDynamicColor,
                subtitle = stringResource(R.string.dynamic_color_body),
            )
        }
        RowDivider()
        SettingsRow(
            Icons.AutoMirrored.Filled.Sort,
            stringResource(R.string.sort_title),
            subtitle = stringResource(sortLabel(settings.sortMode)),
            onClick = { open(Picker.SORT) },
        )
        RowDivider()
        SettingsSwitchRow(
            Icons.Filled.GridView,
            stringResource(R.string.grid_title),
            checked = settings.gridLayout,
            onCheckedChange = actions.onGridLayout,
            subtitle = stringResource(R.string.grid_body),
        )
    }
}

@Composable
private fun DataGroup(
    statusText: String?,
    actions: SettingsActions,
) {
    SettingsGroup(stringResource(R.string.section_backup)) {
        SettingsRow(
            Icons.Filled.FileDownload,
            stringResource(R.string.export_encrypted),
            subtitle = stringResource(R.string.export_encrypted_body),
            onClick = actions.onExportEncrypted,
        )
        RowDivider()
        SettingsRow(
            Icons.Filled.Warning,
            stringResource(R.string.export_plain),
            subtitle = stringResource(R.string.export_plain_body),
            onClick = actions.onExportPlain,
            danger = true,
        )
        RowDivider()
        SettingsRow(
            Icons.Filled.FileUpload,
            stringResource(R.string.import_file),
            subtitle = stringResource(R.string.import_file_body),
            onClick = actions.onImport,
        )
        RowDivider()
        SettingsRow(Icons.Filled.Delete, stringResource(R.string.trash), onClick = actions.onTrash)
        if (statusText != null) {
            RowDivider()
            SettingsRow(Icons.Filled.AdminPanelSettings, statusText)
        }
    }
}

@Composable
private fun AboutGroup(version: String) {
    SettingsGroup(stringResource(R.string.section_about)) {
        Row(
            Modifier.fillMaxWidth().padding(Space.Lg),
            horizontalArrangement = Arrangement.spacedBy(Space.Lg),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            UotpLogo(size = 56.dp)
            Column {
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge)
                Text(
                    stringResource(R.string.about_version, version),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        RowDivider()
        SettingsRow(
            Icons.Filled.Gavel,
            stringResource(R.string.about_license_title),
            subtitle = stringResource(R.string.about_license_body),
        )
        RowDivider()
        SettingsRow(Icons.Filled.Code, stringResource(R.string.about_icons_title), subtitle = stringResource(R.string.about_icons_body))
    }
}
