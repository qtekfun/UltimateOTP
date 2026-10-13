// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.auth.Notice
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import com.qtekfun.ultimateotp.core.vault.secure.KeyInvalidatedException
import com.qtekfun.ultimateotp.core.vault.secure.SecretStore
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.ui.sync.LoginStep
import com.qtekfun.ultimateotp.ui.sync.LoginViewModel
import com.qtekfun.ultimateotp.ui.sync.SignupStep
import com.qtekfun.ultimateotp.ui.sync.SignupViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * The failure mode a green suite never showed: the Keystore key that wraps the vault key is
 * created with `setUserAuthenticationRequired(true)` and a 30 s validity window. Writing a secret
 * needs an authentication newer than that window, and a person who reads an emailed code and
 * types a password needs longer than 30 s. `KeystoreSecretStore.put` then throws
 * `AuthenticationRequiredException`, which used to end the process (KB-3, now closed).
 *
 * [LapsedAuthSecretStore] behaves like that key once the window has lapsed. The device's side of
 * the prompt is played by [answerPrompts]: the root composable and the BiometricPrompt are not
 * here, only the gate's contract with them (a prompt appears, it is answered once).
 *
 * The invariant checked throughout: no uncaught exception, no screen stuck on "working", and the
 * server is never asked to change state while the device cannot store what comes back.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class ExpiredAuthenticationTest {
    private val backend = FakeBackend(signup = true, accountExists = false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val uncaught = CopyOnWriteArrayList<Throwable>()
    private val prompts = AtomicInteger()
    private val gate = AuthGate()
    private var previous: Thread.UncaughtExceptionHandler? = null
    private lateinit var secrets: LapsedAuthSecretStore
    private lateinit var vault: VaultRepository
    private lateinit var context: Context

    /** A `SecretStore` whose key needs an authentication newer than 30 s, like the Keystore key. */
    class LapsedAuthSecretStore : SecretStore {
        private val values = mutableMapOf<String, ByteArray>()

        /** True while the last authentication is inside the validity window. */
        @Volatile var windowOpen = true

        /** True when the key is gone, like after the screen lock was removed. */
        @Volatile var invalidated = false
        override val requiresUserAuthentication = true

        override fun put(
            name: String,
            secret: ByteArray,
        ) {
            checkUsable()
            values[name] = secret.copyOf()
        }

        override fun get(name: String): ByteArray? {
            if (name in values) checkUsable()
            return values[name]?.copyOf()
        }

        override fun delete(name: String) {
            values.remove(name)
        }

        override fun contains(name: String) = name in values

        override fun checkUsable() {
            if (invalidated) throw KeyInvalidatedException()
            if (!windowOpen) throw AuthenticationRequiredException()
        }
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

    /** The root composable's half: shows the prompt, and the person confirms or cancels. */
    private fun answerPrompts(confirm: Boolean): Job =
        scope.launch {
            gate.prompt.filterNotNull().collect { prompt ->
                prompts.incrementAndGet()
                if (confirm) {
                    secrets.windowOpen = true
                    prompt.succeed()
                } else {
                    prompt.fail("Cancel")
                }
            }
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

    private fun engine() = SyncEngine(vault, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })

    private fun signupModel() = SignupViewModel(EmailSignup(engine(), backend.apiFor, nowSeconds = { backend.server.now }), {}, gate)

    /** Email, code and password done: the model waits on the recovery words. */
    private fun signupUpToRecovery(): SignupViewModel {
        runBlocking { vault.create() } // the vault exists: the user was just authenticated
        val model = signupModel()
        model.sendCode(backend.server.url, "new@example.org")
        waitUntilQuiet { model.step.value is SignupStep.Code }
        model.enterCode(requireNotNull(backend.server.codeFor("new@example.org")))
        model.choosePassword("correct horse battery staple")
        waitUntilQuiet { model.step.value is SignupStep.Recovery }
        assertTrue(model.step.value.toString(), model.step.value is SignupStep.Recovery)
        return model
    }

    private fun signups() = backend.server.requests("/otp/v1/signup")

    // ---- first run: the vault key is written ---------------------------------------------------

    @Test
    fun `tapping Create account when the window has lapsed asks to authenticate, then creates`() {
        secrets.windowOpen = false // the first thing a fresh install does is write the vault key
        answerPrompts(confirm = true)
        val model = RootViewModel(vault, gate)
        model.create(FirstRun.SIGN_UP)
        waitUntilQuiet { model.firstRun.value != null }
        noCrash()
        assertEquals(1, prompts.get())
        assertEquals(VaultState.UNLOCKED, vault.state.value)
        assertEquals(FirstRun.SIGN_UP, model.firstRun.value)
        assertNull(gate.notice.value)
    }

    @Test
    fun `using the app offline when the window has lapsed asks to authenticate, then creates`() {
        secrets.windowOpen = false
        answerPrompts(confirm = true)
        val model = RootViewModel(vault, gate)
        model.create(FirstRun.OFFLINE)
        waitUntilQuiet { model.firstRun.value != null }
        noCrash()
        assertEquals(VaultState.UNLOCKED, vault.state.value)
        assertEquals(FirstRun.OFFLINE, model.firstRun.value)
    }

    @Test
    fun `cancelling the prompt at first run leaves the welcome screen, a message, and no vault`() {
        secrets.windowOpen = false
        answerPrompts(confirm = false)
        val model = RootViewModel(vault, gate)
        model.create(FirstRun.SIGN_UP)
        waitUntilQuiet { gate.notice.value != null }
        noCrash()
        assertEquals(Notice.Cancelled, gate.notice.value)
        assertEquals(VaultState.NONE, vault.state.value)
        assertNull(model.firstRun.value)
        assertFalse(secrets.contains(com.qtekfun.ultimateotp.core.vault.VaultRepository.VAULT_KEY))

        // Nothing was half-done: the person tries again, authenticates, and it works.
        gate.noticeShown()
        secrets.windowOpen = true
        model.create(FirstRun.SIGN_UP)
        waitUntilQuiet { vault.state.value == VaultState.UNLOCKED }
        assertEquals(VaultState.UNLOCKED, vault.state.value)
    }

    @Test
    fun `an invalidated key at first run is a message, not a crash`() {
        secrets.invalidated = true
        val model = RootViewModel(vault, gate)
        model.create(FirstRun.SIGN_UP)
        waitUntilQuiet { gate.notice.value != null }
        noCrash()
        assertEquals(Notice.KeyLost, gate.notice.value)
        assertEquals(VaultState.NONE, vault.state.value)
        assertEquals(0, prompts.get())
    }

    @Test
    fun `unlocking with a lapsed window authenticates and unlocks, cancelling stays locked`() {
        runBlocking { vault.create() }
        vault.lock()
        secrets.windowOpen = false
        val cancel = answerPrompts(confirm = false)
        val model = RootViewModel(vault, gate)
        model.unlock()
        waitUntilQuiet { gate.notice.value != null }
        noCrash()
        assertEquals(VaultState.LOCKED, vault.state.value)
        assertEquals(Notice.Cancelled, gate.notice.value)

        cancel.cancel()
        gate.noticeShown()
        answerPrompts(confirm = true)
        model.unlock()
        waitUntilQuiet { vault.state.value == VaultState.UNLOCKED }
        noCrash()
        assertEquals(VaultState.UNLOCKED, vault.state.value)
    }

    @Test
    fun `an invalidated key at unlock is a message and the vault stays locked`() {
        runBlocking { vault.create() }
        vault.lock()
        secrets.invalidated = true
        val model = RootViewModel(vault, gate)
        model.unlock()
        waitUntilQuiet { gate.notice.value != null }
        noCrash()
        assertEquals(Notice.KeyLost, gate.notice.value)
        assertEquals(VaultState.LOCKED, vault.state.value)
    }

    // ---- sign-up: the window lapses while the person reads an email --------------------------

    @Test
    fun `creating the account after the window lapsed authenticates first and then succeeds`() {
        val model = signupUpToRecovery()
        answerPrompts(confirm = true)
        secrets.windowOpen = false // 30 s of reading an email and typing a password
        model.confirmRecoverySaved()
        waitUntilQuiet { model.step.value is SignupStep.Done }
        noCrash()
        assertEquals(SignupStep.Done, model.step.value)
        assertEquals(1, prompts.get())
        assertEquals(1, signups())
        assertTrue(backend.server.hasAccount)
        assertNotNull(runBlocking { vault.account() })
    }

    @Test
    fun `cancelling at the end of sign-up sends nothing, keeps the words, and can be retried`() {
        val model = signupUpToRecovery()
        val words = (model.step.value as SignupStep.Recovery).words
        val cancel = answerPrompts(confirm = false)
        secrets.windowOpen = false
        model.confirmRecoverySaved()
        waitUntilQuiet { gate.notice.value != null }
        waitUntilQuiet { model.step.value !is SignupStep.Working }
        noCrash()
        // The preflight ran before /signup: the server never heard of this account.
        assertEquals(0, signups())
        assertFalse(backend.server.hasAccount)
        assertNull(runBlocking { vault.account() })
        assertEquals(Notice.Cancelled, gate.notice.value)
        assertEquals(SignupStep.Recovery(words), model.step.value)

        // A retry after authenticating is not met by email_taken: the account was never made.
        cancel.cancel()
        answerPrompts(confirm = true)
        model.confirmRecoverySaved()
        waitUntilQuiet { model.step.value is SignupStep.Done }
        noCrash()
        assertEquals(SignupStep.Done, model.step.value)
        assertEquals(1, signups())
        assertTrue(backend.server.hasAccount)
    }

    @Test
    fun `an invalidated key at the end of sign-up sends nothing and says why`() {
        val model = signupUpToRecovery()
        secrets.invalidated = true
        model.confirmRecoverySaved()
        waitUntilQuiet { gate.notice.value != null }
        waitUntilQuiet { model.step.value !is SignupStep.Working }
        noCrash()
        assertEquals(0, signups())
        assertEquals(Notice.KeyLost, gate.notice.value)
        assertTrue(model.step.value.toString(), model.step.value is SignupStep.Recovery)
    }

    // ---- login: the step that stores the vault key -------------------------------------------

    /** The account of another phone is on the server; this phone has its own empty vault. */
    private fun ownerOnServer() {
        runBlocking {
            val first =
                com.qtekfun.ultimateotp.core.sync.fake
                    .InMemorySyncStore()
            val owner = SyncEngine(first, backend.apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
            backend.server.signupEnabled = true
            val signup = EmailSignup(owner, backend.apiFor, nowSeconds = { backend.server.now })
            signup.requestCode(backend.server.url, "owner@example.org")
            val draft = signup.prepare("correct horse")
            draft.confirmRecoverySaved()
            signup.create(backend.server.url, "owner@example.org", backend.server.codeFor("owner@example.org").orEmpty(), draft, "First")
            vault.create()
        }
    }

    private fun loginAtPassword(): Pair<LoginViewModel, LoginStep.Password> {
        ownerOnServer()
        val controller = SyncController(context, vault, scope, gate)
        val model = LoginViewModel(SrpEmailLogin(engine(), backend.apiFor), controller, gate)
        model.sendCode(backend.server.url, "owner@example.org")
        waitUntilQuiet { model.step.value is LoginStep.Code }
        val ticket = (model.step.value as LoginStep.Code)
        model.verify(ticket, requireNotNull(backend.server.codeFor("owner@example.org")))
        waitUntilQuiet { model.step.value is LoginStep.Password }
        return model to model.step.value as LoginStep.Password
    }

    private fun verifies() = backend.server.requests("/otp/v1/srp/verify")

    @Test
    fun `logging in after the window lapsed authenticates first and then succeeds`() {
        val (model, password) = loginAtPassword()
        answerPrompts(confirm = true)
        secrets.windowOpen = false
        model.complete(password, "correct horse", "Pixel")
        waitUntilQuiet { model.step.value is LoginStep.Done }
        noCrash()
        assertEquals(LoginStep.Done, model.step.value)
        assertEquals(1, prompts.get())
        assertEquals(1, verifies())
        assertNotNull(runBlocking { vault.account() })
    }

    @Test
    fun `cancelling at login sends no proof, keeps the code valid and the password step`() {
        val (model, password) = loginAtPassword()
        val cancel = answerPrompts(confirm = false)
        secrets.windowOpen = false
        model.complete(password, "correct horse", "Pixel")
        waitUntilQuiet { gate.notice.value != null }
        waitUntilQuiet { model.step.value !is LoginStep.Working }
        noCrash()
        assertEquals(0, verifies())
        assertEquals(Notice.Cancelled, gate.notice.value)
        assertEquals(password, model.step.value)
        assertNull(runBlocking { vault.account() })

        // Same SRP session, same emailed code: only the authentication was missing.
        cancel.cancel()
        answerPrompts(confirm = true)
        model.complete(password, "correct horse", "Pixel")
        waitUntilQuiet { model.step.value is LoginStep.Done }
        noCrash()
        assertEquals(LoginStep.Done, model.step.value)
        assertEquals(1, verifies())
    }

    @Test
    fun `an invalidated key at login sends no proof and returns to the password step`() {
        val (model, password) = loginAtPassword()
        secrets.invalidated = true
        model.complete(password, "correct horse", "Pixel")
        waitUntilQuiet { gate.notice.value != null }
        waitUntilQuiet { model.step.value !is LoginStep.Working }
        noCrash()
        assertEquals(0, verifies())
        assertEquals(Notice.KeyLost, gate.notice.value)
        assertEquals(password, model.step.value)
    }

    // ---- the gate itself ---------------------------------------------------------------------

    @Test
    fun `two operations that need authentication share one prompt`() {
        secrets.windowOpen = false
        answerPrompts(confirm = true)
        val results = CopyOnWriteArrayList<Any>()
        val jobs =
            List(2) {
                scope.launch { results += gate.run { secrets.put("x$it", byteArrayOf(1)) } }
            }
        runBlocking { jobs.forEach { it.join() } }
        assertEquals(2, results.size)
        assertEquals(1, prompts.get())
        assertTrue(secrets.contains("x0") && secrets.contains("x1"))
    }

    @Test
    fun `an unexpected exception through attempt becomes a notice, not a crash`() {
        val model = RootViewModel(vault, gate)
        runBlocking { vault.create() }
        model.create(FirstRun.OFFLINE) // "vault exists": the kind of bug that must not kill the app
        waitUntilQuiet { gate.notice.value != null }
        noCrash()
        assertTrue(gate.notice.value.toString(), gate.notice.value is Notice.Failed)
    }

    @Test
    fun `the harness itself sees an exception nobody caught`() {
        // Guards the tests above against passing because nothing was observed.
        // A plain thread, not a coroutine: kotlinx-coroutines-test would keep a coroutine's
        // uncaught exception and fail the next runTest in this JVM with it.
        val thread = Thread { throw AuthenticationRequiredException() }
        thread.start()
        thread.join()
        assertTrue(
            "expected the exception to reach the default handler: $uncaught",
            uncaught.any { it is AuthenticationRequiredException },
        )
        uncaught.clear()
    }
}
