// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.FakeUotpServer
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Every request that changes server state is preceded by a check that the device can store what
 * comes back (KB-3). A store that refuses must see no request at all: the account, device or
 * enrollment token is not consumed, so the same action succeeds once the user has authenticated.
 */
class PreflightTest {
    /** Stands for the Keystore's `AuthenticationRequiredException`, which this module cannot name. */
    private class Refused : Exception("authentication required")

    private val server = FakeUotpServer(signupEnabled = true, accountExists = false)
    private val http = OkHttpClient()
    private val apiFor = { url: String -> UotpApi(url, http, nowSeconds = { server.now }) }
    private val store = InMemorySyncStore()
    private val engine = SyncEngine(store, apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })

    @AfterEach
    fun close() = server.close()

    @Test
    fun `sign-up sends nothing while secrets cannot be stored, and works after`(): Unit =
        runBlocking {
            val signup = EmailSignup(engine, apiFor, nowSeconds = { server.now })
            signup.requestCode(server.url, "new@example.org")
            val draft = signup.prepare("correct horse battery")
            draft.confirmRecoverySaved()
            val code = server.codeFor("new@example.org").orEmpty()

            store.refuseSecrets = Refused()
            assertThrows<Refused> { runBlocking { signup.create(server.url, "new@example.org", code, draft, "Phone") } }
            assertEquals(0, server.requests("/otp/v1/signup"))
            assertTrue(!server.hasAccount)
            assertNull(store.account())

            store.refuseSecrets = null
            signup.create(server.url, "new@example.org", code, draft, "Phone")
            assertEquals(1, server.requests("/otp/v1/signup"))
            assertNotNull(store.account())
        }

    @Test
    fun `a failing first sync does not fail a sign-up that already created the account`(): Unit =
        runBlocking {
            val signup = EmailSignup(engine, apiFor, nowSeconds = { server.now })
            signup.requestCode(server.url, "new@example.org")
            val draft = signup.prepare("correct horse battery")
            draft.confirmRecoverySaved()
            server.failNext("/otp/v1/vault", 500, "internal_error")
            val code = server.codeFor("new@example.org").orEmpty()
            signup.create(server.url, "new@example.org", code, draft, "Phone")
            assertTrue(server.hasAccount)
            assertNotNull(store.account())
        }

    @Test
    fun `bootstrap and enrollment spend no token while secrets cannot be stored`(): Unit =
        runBlocking {
            store.refuseSecrets = Refused()
            assertThrows<Refused> { runBlocking { engine.bootstrap(server.url, server.issueToken(), "correct horse", "A") } }
            assertEquals(0, server.requests("/otp/v1/enroll"))

            store.refuseSecrets = null
            engine.bootstrap(server.url, server.issueToken(), "correct horse", "A")

            val other = InMemorySyncStore()
            val second = SyncEngine(other, apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
            other.refuseSecrets = Refused()
            val token = server.issueToken()
            assertThrows<Refused> { runBlocking { second.enrollWithPassword(server.url, token, "correct horse", "B") } }
            assertEquals(1, server.requests("/otp/v1/enroll"))
            other.refuseSecrets = null
            second.enrollWithPassword(server.url, token, "correct horse", "B") // the same token still works
            assertEquals(2, server.requests("/otp/v1/enroll"))
        }

    @Test
    fun `login sends no proof while secrets cannot be stored and keeps the session for the retry`(): Unit =
        runBlocking {
            val owner = InMemorySyncStore()
            val ownerEngine = SyncEngine(owner, apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })
            val ownerSignup = EmailSignup(ownerEngine, apiFor, nowSeconds = { server.now })
            ownerSignup.requestCode(server.url, "owner@example.org")
            val draft = ownerSignup.prepare("correct horse")
            draft.confirmRecoverySaved()
            ownerSignup.create(server.url, "owner@example.org", server.codeFor("owner@example.org").orEmpty(), draft, "Owner")

            val login = SrpEmailLogin(engine, apiFor)
            val (ticket, _) = login.requestCode(server.url, "owner@example.org")
            login.verifyCode(ticket, server.codeFor("owner@example.org").orEmpty())

            store.refuseSecrets = Refused()
            assertThrows<Refused> { runBlocking { login.complete(ticket, "correct horse", "Phone") } }
            assertEquals(0, server.requests("/otp/v1/srp/verify"))

            store.refuseSecrets = null
            login.complete(ticket, "correct horse", "Phone") // same session, same emailed code
            assertEquals(1, server.requests("/otp/v1/srp/verify"))
            assertNotNull(store.account())
        }
}
