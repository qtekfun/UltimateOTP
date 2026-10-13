// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import android.content.Context
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.ui.sync.SyncScreen
import com.qtekfun.ultimateotp.ui.sync.SyncViewModel
import com.qtekfun.ultimateotp.util.AppSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.annotation.Config

/** The "Sync and devices" screen without and with an account, at both window sizes and across a fold. */
@RunWith(ParameterizedRobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class SyncScreenUiTest(
    private val screen: Screen,
) {
    @get:Rule val rule = createEmptyComposeRule()
    private val ui = Ui(rule)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val calls = mutableListOf<String>()
    private lateinit var vault: VaultRepository
    private lateinit var controller: SyncController
    private lateinit var context: Context

    private val host =
        Host(rule) {
            val model =
                viewModel<SyncViewModel>(
                    factory = viewModelFactory { initializer { SyncViewModel(controller, vault, AppSettings(context), AuthGate()) } },
                )
            SyncScreen(
                initialLink = "",
                onBack = { calls += "back" },
                onLogin = { calls += "login" },
                onSignup = { calls += "signup" },
                model = model,
            )
        }

    @Before
    fun setUp() {
        Sodium.init()
        context = ApplicationProvider.getApplicationContext()
        val db = Room.inMemoryDatabaseBuilder<VaultDatabase>(context).setDriver(AndroidSQLiteDriver()).build()
        vault = VaultRepository(db.dao(), InMemorySecretStore())
        runBlocking { vault.create() }
        controller = SyncController(context, vault, scope, AuthGate())
    }

    @After
    fun tearDown() = scope.cancel()

    @Test
    fun `without an account it offers sign-up and login, and they navigate`() {
        host.start(screen)
        ui.see(string(R.string.sync_intro))
        ui.tap(string(R.string.welcome_signup))
        ui.tap(string(R.string.login_title))
        assertEquals(listOf("signup", "login"), calls)
        // The advanced token form stays folded away until asked for.
        ui.notSee(string(R.string.create_account))
        ui.tap(string(R.string.advanced_token))
        ui.see(string(R.string.create_account))
    }

    @Test
    fun `with an account it shows the server and sync controls, also after a fold`() {
        runBlocking {
            vault.apply(
                emptyList(),
                emptyList(),
                AccountState(serverUrl = "https://otp.example.org", accountId = "acc_x", deviceId = "dev_x", label = "Pixel"),
            )
            controller.refresh()
        }
        host.start(screen)
        ui.waitFor(string(R.string.sync_now))
        ui.see(string(R.string.account_status, "https://otp.example.org", 0))
        host.configurationChange(Screen.entries.first { it != screen })
        ui.waitFor(string(R.string.sync_now))
        ui.see(string(R.string.account_status, "https://otp.example.org", 0))
    }

    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun screens(): List<Array<Any>> = Screen.entries.map { arrayOf(it) }
    }
}
