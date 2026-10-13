// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.ui.sync.LoginScreen
import com.qtekfun.ultimateotp.ui.sync.LoginStep
import com.qtekfun.ultimateotp.ui.sync.LoginViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Log in on a second device through the screens: email, emailed code, password, SRP, vault key,
 * first sync. A wrong code and a wrong password take the user back one step without losing the
 * view model; the screens survive being folded between the steps.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class LoginUiTest(
    private val screen: Screen,
) {
    @get:Rule val rule = createEmptyComposeRule()
    private val backend = FakeBackend(signup = false, accountExists = true)
    private val ui = Ui(rule)
    private val password = "correct horse"
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var done = false
    private lateinit var vault: VaultRepository
    private lateinit var controller: SyncController
    private lateinit var model: LoginViewModel

    private val host =
        Host(rule) {
            val m =
                viewModel<LoginViewModel>(
                    factory = viewModelFactory { initializer { LoginViewModel(SrpEmailLogin(engine(), backend.apiFor), controller) } },
                )
            model = m
            LoginScreen(defaultServer = "", label = "Pixel", onBack = { done = true }, model = m)
        }

    /** The phone that logs in: its own empty vault, and the first phone is already on the server. */
    private fun engine(): SyncEngine = SyncEngine(vault, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })

    @Before
    fun setUp() {
        Sodium.init()
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val db =
            androidx.room3.Room
                .inMemoryDatabaseBuilder<VaultDatabase>(context)
                .setDriver(androidx.sqlite.driver.AndroidSQLiteDriver())
                .build()
        vault = VaultRepository(db.dao(), InMemorySecretStore())
        controller = SyncController(context, vault, appScope)
        runBlocking {
            vault.create()
            // The first phone owns the account (a bootstrap with one entry).
            val first = InMemorySyncStore()
            first.add(OtpAuthUri.parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP"))
            val engine = SyncEngine(first, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
            engine.bootstrap(backend.server.url, backend.server.issueToken(), password, "First phone")
            engine.sync()
        }
    }

    @After
    fun tearDown() {
        appScope.cancel()
        backend.close()
    }

    private fun emailStep() {
        host.start(screen)
        ui.type(0, backend.server.url)
        ui.type(1, backend.server.email)
        ui.tap(string(R.string.send_code))
        ui.waitFor(string(R.string.verify))
    }

    @Test
    fun `email, code, password, then this phone has the first phone's entries`() {
        emailStep()
        ui.type(0, requireNotNull(backend.server.codeFor(backend.server.email)))
        ui.tap(string(R.string.verify))
        ui.waitFor(string(R.string.sign_in))
        ui.type(0, password)
        ui.tap(string(R.string.sign_in))
        ui.waitFor(string(R.string.login_done), 60_000)
        assertTrue(model.step.value is LoginStep.Done)
        assertNotNull(runBlocking { vault.account() })
        val result = runBlocking { engine().sync() }
        assertTrue(result.toString(), result is SyncResult.Synced)
        assertEquals(listOf("alice"), runBlocking { vault.items.first() }.map { it.otp.label })
        ui.tap(string(R.string.ok))
        assertTrue(done)
    }

    @Test
    fun `a wrong code is explained and the step is kept across a fold`() {
        emailStep()
        ui.type(0, "000000")
        ui.tap(string(R.string.verify))
        ui.waitFor(string(R.string.wrong_code))
        host.configurationChange(Screen.entries.first { it != screen })
        ui.see(string(R.string.wrong_code))
        ui.see(string(R.string.verify))
    }

    @Test
    fun `a wrong password goes back to the start with the explanation, and the right one then works`() {
        emailStep()
        ui.type(0, requireNotNull(backend.server.codeFor(backend.server.email)))
        ui.tap(string(R.string.verify))
        ui.waitFor(string(R.string.sign_in))
        ui.type(0, "not the password")
        ui.tap(string(R.string.sign_in))
        ui.waitFor(string(R.string.wrong_password_again), 60_000)
        assertNull(runBlocking { vault.account() })
    }

    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun screens(): List<Array<Any>> = Screen.entries.map { arrayOf(it) }
    }
}
