// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.autofill

import android.app.Application
import android.content.Context
import android.view.View
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class AutofillResponsesTest {
    private lateinit var context: Context
    private lateinit var db: VaultDatabase
    private lateinit var vault: VaultRepository

    @Before
    fun setUp() {
        Sodium.init()
        context = ApplicationProvider.getApplicationContext()
        db = Room.inMemoryDatabaseBuilder<VaultDatabase>(context).setDriver(AndroidSQLiteDriver()).build()
        vault = VaultRepository(db.dao(), InMemorySecretStore())
        runBlocking { vault.create() }
    }

    @After
    fun tearDown() = db.close()

    private fun add(issuer: String) =
        runBlocking { vault.add(OtpAuthUri.parse("otpauth://totp/$issuer:u?secret=JBSWY3DPEHPK3PXP&issuer=$issuer")) }

    @Test
    fun `candidates carry the id and issuer of every entry`() {
        val items = listOf(add("GitHub"), add("Dropbox"))
        val candidates = AutofillResponses.candidates(items)
        assertEquals(items.map { it.id.toString() }, candidates.map { it.id })
    }

    @Test
    fun `matching never matches the app itself and ignores a package for web forms`() {
        val items = listOf(add("GitHub"))
        assertEquals(emptyList<Any>(), AutofillResponses.matches(items, "com.qtekfun.ultimateotp", null, "com.qtekfun.ultimateotp"))
        AutofillResponses.matches(items, "com.android.chrome", "github.com", "com.qtekfun.ultimateotp")
    }

    @Test
    fun `the unlock and dataset responses are built, an empty one is not`() {
        val item = add("GitHub")
        val fields = listOf(View(context), View(context)).map { requireNotNull(it.autofillId) }
        assertNotNull(AutofillResponses.unlockResponse(context, fields, "com.example", null))
        assertNotNull(AutofillResponses.datasetsResponse(context, listOf(item, add("Dropbox")), fields))
        assertNull(AutofillResponses.datasetsResponse(context, emptyList(), fields))
        assertNull(AutofillResponses.datasetsResponse(context, listOf(item), emptyList()))
    }
}
