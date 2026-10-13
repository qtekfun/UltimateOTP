// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.screenshots

import androidx.compose.runtime.Composable
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsNodeInteractionCollection
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.performTextInput
import com.qtekfun.ultimateotp.ui.sync.SignupContent
import com.qtekfun.ultimateotp.ui.sync.SignupStep
import com.qtekfun.ultimateotp.ui.theme.UotpTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Folding, unfolding or rotating recreates the activity: what was typed in a form must survive.
 * Plain fields use `rememberSaveable`; passwords and keys use `rememberRetainedText`, which lives in
 * the view-model store and never in the saved instance state.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(application = android.app.Application::class, sdk = [34])
class RecreateTest {
    @get:Rule val rule = createComposeRule()

    @Composable
    private fun Signup(step: SignupStep) {
        UotpTheme {
            SignupContent(
                step = step,
                defaultServer = "",
                onBack = {},
                onLogin = {},
                onSendCode = { _, _ -> },
                onCode = {},
                onResend = {},
                onPassword = {},
                onRecoveryConfirmed = {},
                onRetry = {},
                onRestart = {},
                onCopyWords = {},
            )
        }
    }

    private fun fields(): SemanticsNodeInteractionCollection = rule.onAllNodes(hasSetTextAction())

    private fun texts(): List<String> = fields().fetchSemanticsNodes().map { it.config[SemanticsProperties.EditableText].text }

    @Test
    fun serverAndEmailSurviveRecreation() {
        val tester = StateRestorationTester(rule)
        tester.setContent { Signup(SignupStep.Email) }
        fields()[0].performTextInput("https://otp.example.org")
        fields()[1].performTextInput("alice@example.org")
        tester.emulateSavedInstanceStateRestore()
        assertEquals(listOf("https://otp.example.org", "alice@example.org"), texts())
    }

    @Test
    fun passwordsSurviveRecreation() {
        val tester = StateRestorationTester(rule)
        tester.setContent { Signup(SignupStep.Password) }
        fields()[0].performTextInput("correct horse battery staple")
        fields()[1].performTextInput("correct horse battery staple")
        tester.emulateSavedInstanceStateRestore()
        // The semantics expose the masked text: same length as what was typed.
        val masked = "\u2022".repeat("correct horse battery staple".length)
        assertEquals(listOf(masked, masked), texts())
    }
}
