// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.crypto.Bip39
import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.api.NewDevice
import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.SignupRequest
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.FakeUotpServer
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Account creation from the app (contract 1.1.0 `POST /otp/v1/signup`) against the fake server. */
class SignupTest {
    private val servers = mutableListOf<FakeUotpServer>()
    private val http = OkHttpClient()
    private val cheap = { listOf(2L to (16L shl 20)) }

    @AfterEach
    fun close() = servers.forEach { it.close() }

    private fun server(
        signup: Boolean = true,
        accountExists: Boolean = false,
    ) = FakeUotpServer(signup, accountExists).also { servers += it }

    private class Phone(
        val store: InMemorySyncStore,
        val engine: SyncEngine,
        val signup: EmailSignup,
        val login: SrpEmailLogin,
    )

    private fun phone(server: FakeUotpServer): Phone {
        val store = InMemorySyncStore()
        val apiFor = { url: String -> UotpApi(url, http, nowSeconds = { server.now }) }
        val engine = SyncEngine(store, apiFor, kdfLadder = cheap)
        return Phone(store, engine, EmailSignup(engine, apiFor, nowSeconds = { server.now }), SrpEmailLogin(engine, apiFor))
    }

    private fun otp(label: String) = OtpAuthUri.parse("otpauth://totp/Ex:$label?secret=JBSWY3DPEHPK3PXP")

    private fun problem(block: suspend () -> Unit): AccountProblem {
        val error = assertThrows<Exception> { runBlocking { block() } }
        return requireNotNull(AccountProblem.of(error)) { "not an account problem: $error" }
    }

    @Test
    fun `sign-up uploads the offline entries, then a second phone logs in and decrypts them`(): Unit =
        runBlocking {
            val server = server()
            val a = phone(server)
            a.store.add(otp("alice"))
            a.store.add(otp("bob"))

            val resendAt = a.signup.requestCode(server.url, "  New@Example.org ")
            assertEquals(server.now + EmailSignup.RESEND_COOLDOWN_S, resendAt)
            val code = requireNotNull(server.codeFor("new@example.org")) { "no code emailed" }

            val draft = a.signup.prepare("correct horse battery")
            assertEquals(24, draft.recoveryWords.size)
            assertTrue(draft.recoveryWords.all { it in Bip39.wordlist })
            // Nothing is sent before the user confirms the recovery key.
            assertThrows<IllegalStateException> { runBlocking { a.signup.create(server.url, "new@example.org", code, draft, "Phone A") } }
            assertEquals(0, server.requests("/otp/v1/signup"))
            draft.confirmRecoverySaved()

            val first = a.signup.create(server.url, "New@Example.org", code, draft, "Phone A")
            assertEquals(SyncResult.Synced(version = 1, committed = 2, conflicts = 0), first)
            assertEquals("new@example.org", server.email)
            assertEquals(2, server.state.items.size)
            val account = requireNotNull(a.store.account())
            assertEquals(server.url, account.serverUrl)
            assertEquals(1L, account.acceptedVersion)

            // A second phone: email, emailed code, password (decision 13), then sync.
            val b = phone(server)
            val (ticket, _) = b.login.requestCode(server.url, "new@example.org")
            b.login.verifyCode(ticket, server.codeFor("new@example.org")!!)
            b.login.complete(ticket, "correct horse battery", "Phone B")
            assertInstanceOf(SyncResult.Synced::class.java, b.engine.sync())
            assertEquals(listOf("alice", "bob"), b.store.items().map { it.otp.label })
            assertEquals(
                setOf("signup", "password"),
                b.engine
                    .sessions()
                    .map { it.enrolledVia }
                    .toSet(),
            )

            // The 24 words shown at sign-up open the vault key too (recovery path).
            val c = phone(server)
            c.engine.enrollWithRecoveryKey(server.url, server.issueToken(), draft.recoveryWords.joinToString(" "), "Phone C")
            c.engine.sync()
            assertEquals(listOf("alice", "bob"), c.store.items().map { it.otp.label })
        }

    @Test
    fun `sign-up closed on the server`(): Unit =
        runBlocking {
            val server = server(signup = false)
            val a = phone(server)
            a.signup.requestCode(server.url, "new@example.org")
            assertNull(server.codeFor("new@example.org"), "no code for a new address while sign-up is closed")
            val draft = a.signup.prepare("correct horse battery").also { it.confirmRecoverySaved() }
            assertEquals(AccountProblem.SignupDisabled, problem { a.signup.create(server.url, "new@example.org", "123456", draft, "A") })
            assertNull(a.store.account())
            assertTrue(!server.hasAccount)
        }

    @Test
    fun `an address with an account is taken`(): Unit =
        runBlocking {
            val server = server(accountExists = true)
            val a = phone(server)
            a.signup.requestCode(server.url, server.email)
            val draft = a.signup.prepare("correct horse battery").also { it.confirmRecoverySaved() }
            val code = server.codeFor(server.email)!!
            assertEquals(AccountProblem.EmailTaken, problem { a.signup.create(server.url, server.email, code, draft, "A") })
            assertNull(a.store.account())
        }

    @Test
    fun `a wrong code can be retried, a resent code replaces the old one, the draft is kept`(): Unit =
        runBlocking {
            val server = server()
            val a = phone(server)
            a.store.add(otp("alice"))
            a.signup.requestCode(server.url, "new@example.org")
            val old = server.codeFor("new@example.org")!!
            val draft = a.signup.prepare("correct horse battery").also { it.confirmRecoverySaved() }
            val wrong = if (old == "000000") "111111" else "000000"
            assertEquals(AccountProblem.InvalidCode, problem { a.signup.create(server.url, "new@example.org", wrong, draft, "A") })
            a.signup.requestCode(server.url, "new@example.org")
            val fresh = server.codeFor("new@example.org")!!
            assertTrue(old != fresh)
            assertEquals(AccountProblem.InvalidCode, problem { a.signup.create(server.url, "new@example.org", old, draft, "A") })
            // Same password and recovery words: only the code is asked again.
            assertInstanceOf(SyncResult.Synced::class.java, a.signup.create(server.url, "new@example.org", fresh, draft, "A"))
            assertEquals(1, server.state.items.size)
        }

    @Test
    fun `rate limits and lockouts carry retry_after`(): Unit =
        runBlocking {
            val server = server()
            val a = phone(server)
            server.failNext("/otp/v1/login/email-code", 429, "rate_limited", retryAfter = 30)
            assertEquals(AccountProblem.RateLimited(30), problem { a.signup.requestCode(server.url, "new@example.org") })

            // Login after too many wrong passwords: `/srp/session` answers 429 account_locked.
            a.signup.requestCode(server.url, "new@example.org")
            val draft = a.signup.prepare("correct horse battery").also { it.confirmRecoverySaved() }
            a.signup.create(server.url, "new@example.org", server.codeFor("new@example.org")!!, draft, "A")
            val b = phone(server)
            val (ticket, _) = b.login.requestCode(server.url, "new@example.org")
            server.failNext("/otp/v1/srp/session", 429, "account_locked", retryAfter = 120)
            assertEquals(
                AccountProblem.AccountLocked(120),
                problem { b.login.verifyCode(ticket, server.codeFor("new@example.org")!!) },
            )
        }

    @Test
    fun `a network error can be retried with the same draft`(): Unit =
        runBlocking {
            val server = server()
            val offline = FakeUotpServer().let { down -> down.url.also { down.close() } }
            val a = phone(server)
            assertEquals(AccountProblem.Network, problem { a.signup.requestCode(offline, "new@example.org") })
            a.signup.requestCode(server.url, "new@example.org")
            val draft = a.signup.prepare("correct horse battery").also { it.confirmRecoverySaved() }
            val code = server.codeFor("new@example.org")!!
            assertEquals(AccountProblem.Network, problem { a.signup.create(offline, "new@example.org", code, draft, "A") })
            assertNull(a.store.account())
            assertInstanceOf(SyncResult.Synced::class.java, a.signup.create(server.url, "new@example.org", code, draft, "A"))
        }

    @Test
    fun `the fake server checks the proof of possession and the key bundle like the contract`(): Unit =
        runBlocking {
            val server = server()
            val a = phone(server)
            val api = UotpApi(server.url, http, nowSeconds = { server.now })
            val bundle = a.engine.newAccountKeys("correct horse battery").bundle
            val device = DeviceKeys.generate()
            val other = DeviceKeys.generate()

            fun request(code: String?) =
                SignupRequest("new@example.org", code, NewDevice(device.ed25519PublicB64u, device.x25519PublicB64u, "A"), bundle)

            suspend fun code(): String {
                api.requestEmailCode("new@example.org")
                return server.codeFor("new@example.org")!!
            }

            val noPassword = request(code()).copy(keys = a.engine.newAccountKeys(null).bundle)
            assertEquals(
                "keys_required",
                assertThrows<ApiException> { runBlocking { api.signup(Signer(device, "pending"), noPassword) } }.code,
            )
            // Signed by another key than the one in the body.
            assertEquals(
                "invalid_signature",
                assertThrows<ApiException> { runBlocking { api.signup(Signer(other, "pending"), request(code())) } }.code,
            )
            // Not the literal `pending`.
            assertEquals(
                "invalid_signature",
                assertThrows<ApiException> { runBlocking { api.signup(Signer(device, "dev_x"), request(code())) } }.code,
            )
            assertTrue(!server.hasAccount)
            val created = api.signup(Signer(device, "pending"), request(code()))
            assertEquals("signup", created.device.enrolledVia)
            assertTrue(server.hasAccount)
        }
}
