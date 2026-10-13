// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import android.content.Context
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.sync.account.AccountManagement
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import com.qtekfun.ultimateotp.features.AccountScreen
import com.qtekfun.ultimateotp.features.AccountViewModel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The account management screen: nothing without an account, a confirm step per action with one. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class AccountScreenUiTest {
    @get:Rule val rule = createEmptyComposeRule()
    private val ui = Ui(rule)
    private lateinit var db: VaultDatabase
    private lateinit var vault: VaultRepository
    private lateinit var backend: FakeBackend
    private lateinit var model: AccountViewModel

    private val host = Host(rule) { AccountScreen(onBack = {}, model = model) }

    @Before
    fun setUp() {
        Sodium.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder<VaultDatabase>(context).setDriver(AndroidSQLiteDriver()).build()
        vault = VaultRepository(db.dao(), InMemorySecretStore())
        backend = FakeBackend()
        runBlocking { vault.create() }
    }

    @After
    fun tearDown() {
        backend.close()
        db.close()
    }

    private fun model() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        model = AccountViewModel(context, AccountManagement(vault, backend.engine, backend.apiFor), vault)
    }

    @Test
    fun `without an account it only says so`() {
        model()
        host.start(Screen.COVER)
        ui.waitFor(string(R.string.account_no_account))
        ui.notSee(string(R.string.account_export))
    }

    @Test
    fun `with an account each action asks for confirmation and can be cancelled`() {
        runBlocking {
            vault.apply(
                emptyList(),
                emptyList(),
                AccountState(serverUrl = "https://otp.example.org", accountId = "acc_x", deviceId = "dev_x", label = "Pixel"),
            )
        }
        model()
        host.start(Screen.INNER)
        ui.waitFor(string(R.string.account_export))
        ui.tap(string(R.string.account_export))
        ui.see(string(R.string.account_confirm_export))
        ui.tap(string(R.string.cancel))
        ui.tap(string(R.string.account_delete))
        ui.see(string(R.string.account_confirm_delete))
        ui.see(string(R.string.account_send_code))
        ui.tap(string(R.string.cancel))
        ui.tap(string(R.string.account_change_email))
        ui.see(string(R.string.account_new_email))
        ui.tap(string(R.string.cancel))
        ui.tap(string(R.string.account_sign_out_others))
        ui.see(string(R.string.account_confirm_others))
        ui.tap(string(R.string.cancel))
        ui.see(string(R.string.account_export))
    }
}
