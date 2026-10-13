// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import com.qtekfun.ultimateotp.core.vault.secure.SecretStore
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.ui.sync.LoginStep
import com.qtekfun.ultimateotp.ui.sync.LoginViewModel
import com.qtekfun.ultimateotp.ui.sync.SignupStep
import com.qtekfun.ultimateotp.ui.sync.SignupViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The failure mode a green suite never showed: the Keystore key that wraps the vault key is
 * created with `setUserAuthenticationRequired(true)` and a 30 s validity window. Writing the
 * first secret needs an authentication newer than that window, and a person who reads an emailed
 * code and types a password needs longer than 30 s. `KeystoreSecretStore.put` then throws
 * `AuthenticationRequiredException`, which is not an `IOException`, a `CryptoException` or an
 * `ApiException`, so none of the view models' handlers match and the coroutine's exception ends
 * the process.
 *
 * [LapsedAuthSecretStore] behaves like that key once the window has lapsed. These tests assert the
 * only acceptable outcomes (no uncaught exception, no screen stuck on "working"); they are
 * disabled until the app handles it (KB-3, docs/testing.md), and fail today.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class ExpiredAuthenticationTest {
    private val backend = FakeBackend(signup = true, accountExists = false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val uncaught = CopyOnWriteArrayList<Throwable>()
    private var previous: Thread.UncaughtExceptionHandler? = null
    private lateinit var secrets: LapsedAuthSecretStore
    private lateinit var vault: VaultRepository
    private lateinit var context: Context

    /** A `SecretStore` whose key needs an authentication newer than 30 s, like the Keystore key. */
    class LapsedAuthSecretStore : SecretStore {
        private val values = mutableMapOf<String, ByteArray>()

        /** True while the last authentication is inside the validity window. */
        var windowOpen = true
        override val requiresUserAuthentication = true

        override fun put(
            name: String,
            secret: ByteArray,
        ) {
            if (!windowOpen) throw AuthenticationRequiredException()
            values[name] = secret.copyOf()
        }

        override fun get(name: String): ByteArray? {
            if (!windowOpen && name in values) throw AuthenticationRequiredException()
            return values[name]?.copyOf()
        }

        override fun delete(name: String) {
            values.remove(name)
        }

        override fun contains(name: String) = name in values
    }

    @Before
    fun setUp() {
        Sodium.init()
        previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught += e }
        context = ApplicationProvider.getApplicationContext()
        val db = Room.inMemoryDatabaseBuilder<VaultDatabase>(context).setDriver(AndroidSQLiteDriver()).build()
        secrets = LapsedAuthSecretStore()
        vault = VaultRepository(db.dao(), secrets)
    }

    @After
    fun tearDown() {
        Thread.setDefaultUncaughtExceptionHandler(previous)
        scope.cancel()
        backend.close()
    }

    private fun idleMain() = shadowOf(android.os.Looper.getMainLooper()).idle()

    private fun waitUntilQuiet(done: () -> Boolean) {
        val deadline = System.nanoTime() + 20_000_000_000L
        while (System.nanoTime() < deadline && uncaught.isEmpty() && !done()) {
            idleMain()
            Thread.sleep(20)
        }
        idleMain()
    }

    private fun noCrash() = assertTrue("an uncaught exception would end the app: $uncaught", uncaught.isEmpty())

    @Ignore(
        "KNOWN BUG KB-3: AuthenticationRequiredException is not handled at first-run create (docs/testing.md)",
    )
    @Test
    fun `tapping Create account when the authentication window has lapsed does not end the app`() {
        secrets.windowOpen = false // the first thing a fresh install does is write the vault key
        val model = RootViewModel(vault)
        model.create(FirstRun.SIGN_UP)
        waitUntilQuiet { vault.state.value != VaultState.NONE }
        noCrash()
    }

    @Ignore(
        "KNOWN BUG KB-3: AuthenticationRequiredException is unhandled where the account is created (docs/testing.md)",
    )
    @Test
    fun `creating the account after the authentication window lapsed ends in a message, not a crash`() {
        runBlocking { vault.create() } // the vault exists: the user was just authenticated
        val engine = SyncEngine(vault, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
        val model = SignupViewModel(EmailSignup(engine, backend.apiFor, nowSeconds = { backend.server.now })) {}
        model.sendCode(backend.server.url, "new@example.org")
        waitUntilQuiet { model.step.value is SignupStep.Code }
        model.enterCode(requireNotNull(backend.server.codeFor("new@example.org")))
        model.choosePassword("correct horse battery staple")
        waitUntilQuiet { model.step.value is SignupStep.Recovery }
        assertTrue(model.step.value.toString(), model.step.value is SignupStep.Recovery)

        secrets.windowOpen = false // 30 s of reading an email and typing a password
        model.confirmRecoverySaved()
        waitUntilQuiet { model.step.value !is SignupStep.Working }
        noCrash()
        // And the server account must not be left behind without the device that made it.
        assertEquals(backend.server.hasAccount, runBlocking { vault.account() } != null)
    }

    @Ignore(
        "KNOWN BUG KB-3: AuthenticationRequiredException is unhandled where a login stores the vault key (docs/testing.md)",
    )
    @Test
    fun `logging in after the authentication window lapsed ends in a message, not a crash`() {
        runBlocking {
            val first =
                com.qtekfun.ultimateotp.core.sync.fake
                    .InMemorySyncStore()
            val engine = SyncEngine(first, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
            backend.server.signupEnabled = true
            val signup = EmailSignup(engine, backend.apiFor, nowSeconds = { backend.server.now })
            signup.requestCode(backend.server.url, "owner@example.org")
            val draft = signup.prepare("correct horse")
            draft.confirmRecoverySaved()
            signup.create(backend.server.url, "owner@example.org", backend.server.codeFor("owner@example.org").orEmpty(), draft, "First")
            vault.create()
        }
        val engine = SyncEngine(vault, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
        val controller = SyncController(context, vault, scope)
        val model = LoginViewModel(SrpEmailLogin(engine, backend.apiFor), controller)
        model.sendCode(backend.server.url, "owner@example.org")
        waitUntilQuiet { model.step.value is LoginStep.Code }
        val ticket = (model.step.value as LoginStep.Code)
        model.verify(ticket, requireNotNull(backend.server.codeFor("owner@example.org")))
        waitUntilQuiet { model.step.value is LoginStep.Password }
        secrets.windowOpen = false
        model.complete(model.step.value as LoginStep.Password, "correct horse", "Pixel")
        waitUntilQuiet { model.step.value !is LoginStep.Working }
        noCrash()
    }

    @Test
    fun `the harness itself sees an uncaught exception from a view model scope`() {
        // Guards the tests above against passing because nothing was observed.
        secrets.windowOpen = false
        RootViewModel(vault).create(FirstRun.SIGN_UP)
        waitUntilQuiet { false }
        assertTrue(
            "expected the lapsed store to throw out of the view model: $uncaught",
            uncaught.any { it is AuthenticationRequiredException },
        )
        uncaught.clear()
    }
}
