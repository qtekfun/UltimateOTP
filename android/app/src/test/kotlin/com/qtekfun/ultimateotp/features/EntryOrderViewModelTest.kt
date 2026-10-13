// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.features

import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The list actions the redesigned screen calls: move(from, to), delete and undo. */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = android.app.Application::class)
class EntryOrderViewModelTest {
    private val db =
        Room
            .inMemoryDatabaseBuilder<VaultDatabase>(ApplicationProvider.getApplicationContext<Context>())
            .setDriver(AndroidSQLiteDriver())
            .build()
    private var now = 1_000L
    private val vault = VaultRepository(db.dao(), InMemorySecretStore(), clock = { now })

    @Before
    fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        db.close()
    }

    /** The ids of the first list of entries that satisfies [done]; the view model works on its own scope. */
    private suspend fun waitFor(done: (List<com.qtekfun.ultimateotp.core.sync.model.VaultItem>) -> Boolean) =
        kotlinx.coroutines.withTimeout(10_000) { vault.items.first(done).map { it.id } }

    private fun secret(i: Int) = "JBSWY3DPEHPK3PX" + "ABCDEFGH"[i]

    @Test
    fun `move, delete and undo go through the vault and the list follows`(): Unit =
        runBlocking {
            vault.create()
            val ids = (0..3).map { vault.add(OtpAuthUri.parse("otpauth://totp/S$it:u?secret=${secret(it)}&issuer=S$it")).id }
            val model = EntryOrderViewModel(vault)
            val job = model.entries.onEach { }.launchIn(kotlinx.coroutines.CoroutineScope(Dispatchers.Main))
            assertEquals(ids, model.entries.first { it.size == 4 }.map { it.id })

            now += 10
            model.move(0, 2)
            assertEquals(listOf(ids[1], ids[2], ids[0], ids[3]), waitFor { it.size == 4 && it[0].id == ids[1] })

            // Out-of-range and no-op moves change nothing.
            model.move(0, 9)
            model.move(-1, 1)
            model.move(1, 1)
            assertEquals(listOf(ids[1], ids[2], ids[0], ids[3]), vault.items.first().map { it.id })

            model.delete(ids[0])
            assertEquals(listOf(ids[1], ids[2], ids[3]), waitFor { it.size == 3 })
            model.undoDelete(ids[0])
            assertTrue(ids[0] in waitFor { it.size == 4 })
            job.cancel()
        }
}
