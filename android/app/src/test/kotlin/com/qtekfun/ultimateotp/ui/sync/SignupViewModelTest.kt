// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.FakeUotpServer
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

/** The sign-up screen's state machine against the contract fake server (JVM, real crypto). */
@OptIn(ExperimentalCoroutinesApi::class)
class SignupViewModelTest {
    private val main = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private val server = FakeUotpServer(signupEnabled = true, accountExists = false)
    private val store = InMemorySyncStore()
    private var refreshed = 0
    private lateinit var model: SignupViewModel

    @BeforeEach
    fun setUp() {
        Dispatchers.setMain(main)
        val apiFor = { url: String -> UotpApi(url, OkHttpClient(), nowSeconds = { server.now }) }
        val engine = SyncEngine(store, apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
        model = SignupViewModel(EmailSignup(engine, apiFor, nowSeconds = { server.now })) { refreshed++ }
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
        main.close()
        server.close()
    }

    private fun <T : SignupStep> await(type: Class<T>): T =
        runBlocking {
            withTimeout(TIMEOUT_MS) { type.cast(model.step.first { type.isInstance(it) }) }
        }

    private val email = "new@example.org"

    @Test
    fun `email, code, password, recovery words, then the account exists and the entries are uploaded`() {
        store.add(OtpAuthUri.parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP"))
        model.sendCode(server.url, " New@Example.org")
        val code = await(SignupStep.Code::class.java)
        assertEquals(email, code.email)
        model.enterCode(server.codeFor(email)!!)
        await(SignupStep.Password::class.java)
        model.choosePassword("abcdefgh") // weak: ignored
        assertEquals(SignupStep.Password, model.step.value)
        model.choosePassword("correct horse battery staple")
        val recovery = await(SignupStep.Recovery::class.java)
        assertEquals(24, recovery.words.size)
        assertEquals(0, server.requests("/otp/v1/signup"))
        model.confirmRecoverySaved()
        await(SignupStep.Done::class.java)
        assertEquals(1, refreshed)
        assertTrue(server.hasAccount)
        assertEquals(1, server.state.items.size)
        assertEquals(server.url, runBlocking { store.account() }!!.serverUrl)
    }

    @Test
    fun `a wrong code goes back to the code step and keeps the confirmed recovery key`() {
        model.sendCode(server.url, email)
        await(SignupStep.Code::class.java)
        val right = server.codeFor(email)!!
        model.enterCode(if (right == "000000") "111111" else "000000")
        await(SignupStep.Password::class.java)
        model.choosePassword("correct horse battery staple")
        await(SignupStep.Recovery::class.java)
        model.confirmRecoverySaved()
        val retry = await(SignupStep.Code::class.java)
        assertTrue(retry.wrongCode)
        model.enterCode(right) // straight to creation: no new password, no new words
        await(SignupStep.Done::class.java)
        assertTrue(server.hasAccount)
    }

    @Test
    fun `closed sign-up offers login, rate limits can be retried`() {
        server.failNext("/otp/v1/login/email-code", 429, "rate_limited", retryAfter = 30)
        model.sendCode(server.url, email)
        assertEquals(SignupStep.Failed(AccountProblem.RateLimited(30), canRetry = true), await(SignupStep.Failed::class.java))
        model.retry()
        await(SignupStep.Code::class.java)
        server.signupEnabled = false
        model.enterCode(server.codeFor(email)!!)
        model.choosePassword("correct horse battery staple")
        await(SignupStep.Recovery::class.java)
        model.confirmRecoverySaved()
        assertEquals(SignupStep.Failed(AccountProblem.SignupDisabled, canRetry = false), await(SignupStep.Failed::class.java))
    }

    private companion object {
        const val TIMEOUT_MS = 30_000L
    }
}
