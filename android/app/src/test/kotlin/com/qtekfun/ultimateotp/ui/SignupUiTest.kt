// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.performClick
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.ui.sync.SignupScreen
import com.qtekfun.ultimateotp.ui.sync.SignupStep
import com.qtekfun.ultimateotp.ui.sync.SignupViewModel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The sign-up screens, tapped through with the real view model, engine and crypto against the
 * contract fake server, at the Pixel 9 Pro Fold's two window sizes. The device is folded and
 * unfolded (a new activity instance, same view model) at every step: the step, the 24 words and
 * the draft keys must survive, because the account is only created after the words are confirmed
 * and the user cannot be shown a different set.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class SignupUiTest(
    private val screen: Screen,
) {
    @get:Rule val rule = createEmptyComposeRule()
    private val backend = FakeBackend()
    private val ui = Ui(rule)
    private val email = "new@example.org"
    private var created: SignupViewModel? = null
    private var built = 0
    private var leftWith: String? = null
    private val host =
        Host(rule) {
            val model =
                viewModel<SignupViewModel>(
                    factory =
                        viewModelFactory {
                            initializer {
                                built++
                                SignupViewModel(
                                    EmailSignup(backend.engine, backend.apiFor, nowSeconds = { backend.server.now }),
                                    {},
                                    AuthGate(),
                                )
                            }
                        },
                )
            created = model
            SignupScreen(
                defaultServer = "",
                label = "Pixel",
                onBack = { leftWith = "back" },
                onLogin = { leftWith = "login" },
                model = model,
            )
        }

    @After
    fun close() = backend.close()

    private fun toCodeStep() {
        host.start(screen)
        ui.type(0, backend.server.url)
        ui.type(1, " New@Example.org ")
        ui.tap(string(R.string.send_code))
        ui.waitFor(string(R.string.next))
    }

    private fun enterCodeAndPassword() {
        ui.type(0, requireNotNull(backend.server.codeFor(email)))
        ui.tap(string(R.string.next))
        ui.waitFor(string(R.string.signup_password_warning))
        ui.type(0, PASSWORD)
        ui.type(1, PASSWORD)
        ui.tap(string(R.string.next))
        ui.waitFor(string(R.string.recovery_title), 60_000)
    }

    private fun words(): List<String> = (created!!.step.value as SignupStep.Recovery).words

    @Test
    fun `the whole sign-up works at this size and creates the account`() {
        backend.store.add(OtpAuthUri.parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP"))
        toCodeStep()
        enterCodeAndPassword()
        assertEquals(24, words().size)
        // Nothing reaches the server before the words are confirmed.
        assertEquals(0, backend.server.requests("/otp/v1/signup"))
        ui.tap(string(R.string.signup_create)) // disabled until the box is ticked: no effect
        assertEquals(0, backend.server.requests("/otp/v1/signup"))

        rule.onNode(isToggleable()).performClick()
        ui.tap(string(R.string.signup_create))
        ui.waitFor(string(R.string.signup_done), 60_000)
        assertTrue(backend.server.hasAccount)
        assertEquals(1, backend.server.state.items.size)
    }

    @Test
    fun `folding and unfolding at every step keeps the step and the confirmed words`() {
        toCodeStep()
        val other = Screen.entries.first { it != screen }
        val before = created
        host.configurationChange(other)
        assertSame("the same view model after the fold", before, created)
        assertEquals(1, built)
        ui.see(string(R.string.next))

        // The code step survived: continue on the other display.
        ui.type(0, requireNotNull(backend.server.codeFor(email)))
        ui.tap(string(R.string.next))
        ui.waitFor(string(R.string.signup_password_warning))
        host.configurationChange(screen)
        assertEquals(1, built)
        ui.see(string(R.string.signup_password_warning))

        ui.type(0, PASSWORD)
        ui.type(1, PASSWORD)
        ui.tap(string(R.string.next))
        ui.waitFor(string(R.string.recovery_title), 60_000)
        val shown = words()

        // Fold and unfold on the words screen: same 24 words, not new keys.
        host.configurationChange(other)
        ui.see(string(R.string.recovery_title))
        assertEquals(shown, words())
        host.configurationChange(screen)
        assertEquals(shown, words())
        assertEquals(1, built)
        assertEquals(0, backend.server.requests("/otp/v1/signup"))

        rule.onNode(isToggleable()).performClick()
        ui.tap(string(R.string.signup_create))
        ui.waitFor(string(R.string.signup_done), 60_000)
        assertTrue(backend.server.hasAccount)
        assertNotEquals(0, host.recreations)
    }

    @Test
    fun `a closed server explains itself at the first step and offers login`() {
        backend.server.signupEnabled = false
        host.start(screen)
        ui.type(0, backend.server.url)
        ui.type(1, "new@example.org")
        ui.tap(string(R.string.send_code))
        // Contract 1.3.0: refused before any email, not after the password and the recovery words.
        ui.waitFor(string(R.string.problem_signup_disabled))
        ui.tap(string(R.string.login_title))
        assertEquals("login", leftWith)
    }

    @Test
    fun `an address that already has an account stops the sign-up at the first step`() {
        val taken = FakeBackend(signup = true, accountExists = true)
        try {
            host.start(screen)
            ui.type(0, taken.server.url)
            ui.type(1, taken.server.email)
            ui.tap(string(R.string.send_code))
            ui.waitFor(string(R.string.problem_email_taken))
            assertEquals(null, taken.server.lastEmailCode)
            ui.tap(string(R.string.login_title))
            assertEquals("login", leftWith)
        } finally {
            taken.close()
        }
    }

    /**
     * The form fields are `remember { mutableStateOf("") }`, not `rememberSaveable`: unfolding the
     * phone half way through the first step empties the server address and the email. Only the
     * step and the draft keys live in the view model.
     */
    @Test
    @Ignore("KNOWN BUG KB-5: sign-up and login form fields are lost on a configuration change (docs/testing.md)")
    fun `text typed into the first step survives a fold`() {
        host.start(screen)
        ui.type(0, backend.server.url)
        ui.type(1, email)
        host.configurationChange(Screen.entries.first { it != screen })
        rule.onAllNodes(hasSetTextAction())[1].assertTextContains(email)
    }

    companion object {
        private const val PASSWORD = "correct horse battery staple"

        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun screens(): List<Array<Any>> = Screen.entries.map { arrayOf(it) }
    }
}
