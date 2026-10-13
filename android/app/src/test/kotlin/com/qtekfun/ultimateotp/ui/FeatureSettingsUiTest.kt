// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.settings.SettingsActions
import com.qtekfun.ultimateotp.ui.settings.SettingsContent
import com.qtekfun.ultimateotp.util.Settings
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The settings of the added features on the redesigned screen: lock timeout picker, navigation rows, error log. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class FeatureSettingsUiTest {
    @get:Rule val rule = createEmptyComposeRule()
    private val ui = Ui(rule)
    private val calls = mutableListOf<String>()
    private var settings by mutableStateOf(Settings(lockTimeoutSeconds = 60))

    private val host =
        Host(rule) {
            SettingsContent(
                settings = settings,
                statusText = null,
                version = "test",
                language = "",
                autofillEnabled = false,
                actions =
                    SettingsActions(
                        onTrash = { calls += "trash" },
                        onAccount = { calls += "account" },
                        onAutofillSettings = { calls += "autofill" },
                        onAutofillAssociations = { calls += "associations" },
                        onShareLog = { calls += "share" },
                        onSaveLog = { calls += "save" },
                        onClearLog = { calls += "clear" },
                        onLockTimeout = { settings = settings.copy(lockTimeoutSeconds = it) },
                    ),
            )
        }

    @Test
    fun `its rows navigate and the log can be shared, saved and cleared`() {
        host.start(Screen.COVER)
        ui.see(string(R.string.section_autofill))
        ui.see(string(R.string.autofill_state_off))
        for (
        id in
        listOf(
            R.string.autofill_associations,
            R.string.autofill_enable,
            R.string.account_settings,
            R.string.trash,
            R.string.diagnostics_share,
            R.string.diagnostics_save,
            R.string.diagnostics_clear,
        )
        ) {
            rule.onNodeWithText(string(id)).performScrollTo().performClick()
        }
        assertEquals(listOf("associations", "autofill", "account", "trash", "share", "save", "clear"), calls)
    }

    @Test
    fun `the lock timeout is picked from a dialog and can be never`() {
        host.start(Screen.COVER)
        ui.tap(string(R.string.lock_timeout_title))
        ui.tap(string(R.string.lock_choice_never))
        assertEquals(-1, settings.lockTimeoutSeconds)
        ui.waitFor(string(R.string.lock_choice_never))
    }
}
