// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.lock.WelcomeScreen
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.annotation.Config

/** The first screen, at the cover display's and the inner display's size, and across a fold. */
@RunWith(ParameterizedRobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class FirstRunUiTest(
    private val screen: Screen,
) {
    @get:Rule val rule = createEmptyComposeRule()
    private val chosen = mutableListOf<FirstRun>()
    private val ui = Ui(rule)
    private val host = Host(rule) { WelcomeScreen(onChoice = { chosen += it }) }

    @Test
    fun `all four ways in are shown and each reports its own choice`() {
        host.start(screen)
        assertEquals(screen.widthDp, host.widthDp())
        listOf(
            R.string.welcome_signup to FirstRun.SIGN_UP,
            R.string.welcome_login to FirstRun.LOG_IN,
            R.string.welcome_offline to FirstRun.OFFLINE,
            R.string.welcome_advanced to FirstRun.ADVANCED,
        ).forEach { (label, expected) ->
            ui.see(string(label))
            ui.tap(string(label))
            assertEquals(expected, chosen.last())
        }
        assertEquals(4, chosen.size)
    }

    @Test
    fun `folding and unfolding keeps the screen and its choices`() {
        host.start(screen)
        val other = Screen.entries.first { it != screen }
        host.configurationChange(other)
        assertEquals(other.widthDp, host.widthDp())
        ui.see(string(R.string.welcome_title))
        ui.tap(string(R.string.welcome_signup))
        host.configurationChange(screen)
        assertEquals(screen.widthDp, host.widthDp())
        ui.tap(string(R.string.welcome_login))
        assertEquals(listOf(FirstRun.SIGN_UP, FirstRun.LOG_IN), chosen)
        assertEquals(2, host.recreations)
    }

    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun screens(): List<Array<Any>> = Screen.entries.map { arrayOf(it) }
    }
}
