// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import android.content.Context
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.support.lock.LockTimeout
import com.qtekfun.ultimateotp.features.FeatureSettingsSection
import com.qtekfun.ultimateotp.features.FeatureSettingsViewModel
import com.qtekfun.ultimateotp.util.AppSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The feature block of the settings screen: lock timeout picker, navigation buttons, error log. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class FeatureSettingsUiTest {
    @get:Rule val rule = createEmptyComposeRule()
    private val ui = Ui(rule)
    private val calls = mutableListOf<String>()
    private lateinit var model: FeatureSettingsViewModel

    private val host =
        Host(rule) {
            FeatureSettingsSection(
                onTrash = { calls += "trash" },
                onAccount = { calls += "account" },
                onAutofillAssociations = { calls += "associations" },
                model = model,
            )
        }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        model = FeatureSettingsViewModel(context, AppSettings(context), testDiagnostics())
    }

    @Test
    fun `its buttons navigate and the log can be shared and cleared`() {
        host.start(Screen.COVER)
        ui.see(string(R.string.section_autofill))
        ui.see(string(R.string.autofill_state_off))
        ui.tap(string(R.string.autofill_associations))
        ui.tap(string(R.string.trash))
        ui.tap(string(R.string.account_settings))
        assertEquals(listOf("associations", "trash", "account"), calls)
        ui.tap(string(R.string.autofill_enable))
        ui.tap(string(R.string.diagnostics_share))
        ui.tap(string(R.string.diagnostics_clear))
        assertFalse(model.autofillEnabled())
    }

    @Test
    fun `the lock timeout is picked from a dialog and kept`() {
        host.start(Screen.INNER)
        // The stored value may be left over from another test in this JVM, so match by prefix.
        val opener = hasText(string(R.string.lock_timeout_title) + ": ", substring = true)
        rule.onNode(opener).performClick()
        ui.tap(string(R.string.lock_choice_5m))
        ui.waitFor(string(R.string.lock_timeout_title) + ": " + string(R.string.lock_choice_5m))
        assertEquals(LockTimeout.MINUTES_5, model.lockTimeout.value)
        // Cancel leaves the dialog without changing anything.
        rule.onNode(opener).performClick()
        ui.tap(string(R.string.cancel))
        ui.notSee(string(R.string.lock_choice_never))
    }
}
