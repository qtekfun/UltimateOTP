// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import android.content.Context
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.performClick
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.history.HistoryRecovery
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import com.qtekfun.ultimateotp.features.TrashScreen
import com.qtekfun.ultimateotp.features.TrashViewModel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The trash screen: local trash actions and the server history lookup without an account. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class TrashScreenUiTest {
    @get:Rule val rule = createEmptyComposeRule()
    private val ui = Ui(rule)
    private val calls = mutableListOf<String>()
    private lateinit var db: VaultDatabase
    private lateinit var vault: VaultRepository
    private lateinit var backend: FakeBackend
    private lateinit var model: TrashViewModel

    private val host = Host(rule) { TrashScreen(onBack = { calls += "back" }, model = model) }

    @Before
    fun setUp() {
        Sodium.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder<VaultDatabase>(context).setDriver(AndroidSQLiteDriver()).build()
        vault = VaultRepository(db.dao(), InMemorySecretStore())
        backend = FakeBackend()
        runBlocking { vault.create() }
        model = TrashViewModel(vault, HistoryRecovery(vault, backend.engine, backend.apiFor), testDiagnostics())
    }

    @After
    fun tearDown() {
        backend.close()
        db.close()
    }

    private fun trashOne(name: String) =
        runBlocking {
            val item = vault.add(OtpAuthUri.parse("otpauth://totp/$name:u?secret=JBSWY3DPEHPK3PXP&issuer=$name"))
            vault.delete(item.id)
            item
        }

    @Test
    fun `an empty trash says so and the server lookup falls back to nothing recoverable`() {
        host.start(Screen.COVER)
        ui.see(string(R.string.trash_empty))
        ui.tap(string(R.string.trash_server_load))
        ui.waitFor(string(R.string.trash_server_none))
        rule.onNodeWithContentDescription(string(R.string.back)).performClick()
        assertEquals(listOf("back"), calls)
    }

    @Test
    fun `restore and delete forever act on the vault`() {
        val restored = trashOne("Alpha")
        val purged = trashOne("Beta")
        host.start(Screen.COVER)
        ui.waitFor("Alpha · u")
        ui.see("Beta · u")
        ui.see(string(R.string.trash_empty_all))
        model.restore(restored.id)
        model.purge(purged.id)
        ui.waitFor(string(R.string.trash_empty))
        assertTrue(runBlocking { vault.items.first() }.any { it.id == restored.id })
    }

    @Test
    fun `emptying the trash removes everything`() {
        trashOne("Alpha")
        host.start(Screen.INNER)
        ui.waitFor(string(R.string.trash_empty_all))
        ui.tap(string(R.string.trash_empty_all))
        ui.waitFor(string(R.string.trash_empty))
    }
}
