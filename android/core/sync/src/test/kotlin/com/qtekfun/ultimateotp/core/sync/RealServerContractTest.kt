// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/**
 * The Android sync engine against the real Python server, as two processes talking HTTP.
 *
 * Everything else in this module runs against `FakeUotpServer`, a second implementation of the
 * contract written by the same people; two implementations that agree with each other can still
 * both be wrong. This test starts `uv run ultimateotp api` on a free loopback port with a temp
 * data directory and drives sign-up, password login on a second device, live events, revocation
 * and a skewed clock through the client's real code paths (real Argon2id parameters are replaced
 * by a cheap rung only to keep the run short; the wire format is the same).
 *
 * Run with `./gradlew :core:sync:contractTest` (needs `uv`; CI job "contract"). It is excluded
 * from `test` so that `./gradlew check` stays hermetic.
 */
@Tag("contract")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RealServerContractTest {
    private lateinit var data: File
    private lateinit var process: Process
    private lateinit var url: String
    private lateinit var log: File
    private val http = OkHttpClient()
    private val cheap = { listOf(2L to (16L shl 20)) }
    private var emails = 0

    @BeforeAll
    fun startServer() {
        val serverDir = File(requireNotNull(System.getProperty("uotp.server.dir")) { "run through Gradle: :core:sync:contractTest" })
        val migrations = requireNotNull(System.getProperty("uotp.migrations.dir"))
        data = Files.createTempDirectory("uotp-contract").toFile()
        log = File(data, "server.log")
        val port = ServerSocket(0).use { it.localPort }
        url = "http://127.0.0.1:$port"
        val env =
            mapOf(
                "UOTP_DATA_DIR" to data.path,
                "UOTP_MIGRATIONS_DIR" to migrations,
                "UOTP_HOST" to "127.0.0.1",
                "UOTP_PORT" to port.toString(),
                "UOTP_SIGNUP" to "enabled",
                "UOTP_EMAIL_VERIFICATION" to "disabled",
                "UOTP_RATELIMIT_ENABLED" to "false",
                "UOTP_SSE_KEEPALIVE_S" to "1",
                "UOTP_LOG_LEVEL" to "INFO",
            )
        run(serverDir, env, "migrate").also {
            assertEquals(
                0,
                it.waitFor(120, TimeUnit.SECONDS).let { done ->
                    if (done) it.exitValue() else -1
                },
                logText(),
            )
        }
        process = run(serverDir, env, "api")
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(STARTUP_S)
        while (true) {
            check(process.isAlive) { "the api exited during startup:\n${logText()}" }
            val up = runCatching { runBlocking { UotpApi(url, http).serverInfo() } }.isSuccess
            if (up) break
            check(System.nanoTime() < deadline) { "the api did not answer within ${STARTUP_S}s:\n${logText()}" }
            Thread.sleep(100)
        }
    }

    @AfterAll
    fun stopServer() {
        if (::process.isInitialized) {
            process.destroy()
            if (!process.waitFor(10, TimeUnit.SECONDS)) process.destroyForcibly()
        }
        if (::data.isInitialized) data.deleteRecursively()
    }

    private fun run(
        serverDir: File,
        env: Map<String, String>,
        vararg args: String,
    ): Process =
        ProcessBuilder(listOf("uv", "run", "--frozen", "--project", serverDir.path, "ultimateotp") + args)
            .apply {
                environment().keys.removeIf { it.startsWith("UOTP_") }
                environment().putAll(env)
                redirectErrorStream(true)
                redirectOutput(ProcessBuilder.Redirect.appendTo(log))
            }.start()

    private fun logText(): String = if (log.exists()) log.readText().takeLast(LOG_TAIL) else "(no log)"

    // ---- helpers ------------------------------------------------------------------------------

    private class Phone(
        val store: InMemorySyncStore,
        val engine: SyncEngine,
        val signup: EmailSignup,
        val login: SrpEmailLogin,
        val api: () -> UotpApi?,
    )

    private fun phone(clock: () -> Long = { System.currentTimeMillis() / MILLIS }): Phone {
        val store = InMemorySyncStore()
        val apis = mutableMapOf<String, UotpApi>()
        val apiFor = { u: String -> apis.getOrPut(u) { UotpApi(u, http, nowSeconds = clock) } }
        val engine = SyncEngine(store, apiFor, kdfLadder = cheap)
        return Phone(
            store,
            engine,
            EmailSignup(engine, apiFor),
            SrpEmailLogin(engine, apiFor),
        ) { runBlocking { store.account() }?.let { apiFor(it.serverUrl) } }
    }

    private fun otp(label: String) = OtpAuthUri.parse("otpauth://totp/Ex:$label?secret=JBSWY3DPEHPK3PXP&issuer=Ex")

    private fun newEmail() = "user${++emails}@example.org"

    private suspend fun signUp(
        phone: Phone,
        email: String,
        password: String = PASSWORD,
        label: String = "Phone A",
    ): List<String> {
        phone.signup.requestCode(url, email)
        val draft = phone.signup.prepare(password)
        draft.confirmRecoverySaved()
        // Email verification is disabled on this server: the code is not checked, only carried.
        val first = phone.signup.create(url, email, "123456", draft, label)
        assertInstanceOf(SyncResult.Synced::class.java, first)
        return draft.recoveryWords
    }

    private suspend fun logIn(
        phone: Phone,
        email: String,
        password: String = PASSWORD,
        label: String = "Phone B",
    ) {
        val (ticket, _) = phone.login.requestCode(url, email)
        assertEquals(false, ticket.codeRequired, "verification is disabled on this server")
        phone.login.complete(phone.login.verifyCode(ticket, ""), password, label)
    }

    private fun signerOf(phone: Phone): Signer? =
        runBlocking { phone.store.account() }?.let { Signer(phone.store.deviceKeys(), it.deviceId) }

    private fun labels(phone: Phone) = phone.store.items().map { it.otp.label }

    // ---- the contract ---------------------------------------------------------------------------

    @Test
    fun `sign-up from the app, then a second device logs in with the password and gets the entries`(): Unit =
        runBlocking {
            val email = newEmail()
            val a = phone()
            a.store.add(otp("alice"))
            a.store.add(otp("bob"))
            val words = signUp(a, email)
            assertEquals(24, words.size)

            val account = requireNotNull(a.store.account())
            assertEquals(url, account.serverUrl)
            assertEquals(1L, account.acceptedVersion)

            val b = phone()
            logIn(b, email)
            assertInstanceOf(SyncResult.Synced::class.java, b.engine.sync())
            assertEquals(listOf("alice", "bob"), labels(b))
            // The secrets, not only the labels: the codes of the two devices agree.
            assertEquals(
                a.store.items().map { it.otp },
                b.store.items().map { it.otp },
            )
            assertEquals(
                setOf("signup", "password"),
                b.engine
                    .sessions()
                    .map { it.enrolledVia }
                    .toSet(),
            )

            // The 24 words from the sign-up screen also open the vault key (recovery path), through a
            // token minted by the server's own CLI.
            val c = phone()
            val token = mintToken(account.accountId)
            c.engine.enrollWithRecoveryKey(url, token, words.joinToString(" "), "Phone C")
            c.engine.sync()
            assertEquals(listOf("alice", "bob"), labels(c))
        }

    @Test
    fun `an edit on one device reaches the other through the live event stream`(): Unit =
        runBlocking {
            val email = newEmail()
            val a = phone()
            signUp(a, email)
            val b = phone()
            logIn(b, email)
            b.engine.sync()
            // A confirms the device it did not pair itself (crypto-format.md §5.2).
            a.engine.devices()
            a.engine.trustDevice(requireNotNull(b.store.account()).deviceId)

            val events = Channel<ServerEvent>(Channel.UNLIMITED)
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val stream =
                EventStream(
                    http,
                    api = { b.api() },
                    signer = { signerOf(b) },
                    onEvent = { events.send(it) },
                )
            stream.start(scope)
            try {
                withTimeout(EVENT_TIMEOUT_MS) {
                    // `hello` first: the stream is open and authenticated.
                    var hello = events.receive()
                    while (hello.type != "hello") hello = events.receive()
                    assertTrue(Json.parseToJsonElement(hello.data).jsonObject["version"] != null, hello.data)
                }
                a.store.add(otp("carol"))
                assertInstanceOf(SyncResult.Synced::class.java, a.engine.sync())
                val vault =
                    withTimeout(EVENT_TIMEOUT_MS) {
                        var event = events.receive()
                        while (event.type != "vault") event = events.receive()
                        event
                    }
                val announced =
                    Json
                        .parseToJsonElement(vault.data)
                        .jsonObject["version"]
                        ?.jsonPrimitive
                        ?.content
                assertEquals(requireNotNull(a.store.account()).acceptedVersion.toString(), announced)
                // What the notification asks for: pull, and the new entry is there.
                assertInstanceOf(SyncResult.Synced::class.java, b.engine.sync())
                assertEquals(listOf("carol"), labels(b))
            } finally {
                stream.stop()
                scope.cancel()
            }
        }

    @Test
    fun `a revoked device is told on its stream and then leaves the account, keeping its entries`(): Unit =
        runBlocking {
            val email = newEmail()
            val a = phone()
            a.store.add(otp("alice"))
            signUp(a, email)
            val b = phone()
            logIn(b, email)
            b.engine.sync()

            val events = Channel<ServerEvent>(Channel.UNLIMITED)
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val stream =
                EventStream(
                    http,
                    api = { b.api() },
                    signer = { signerOf(b) },
                    onEvent = { events.send(it) },
                )
            stream.start(scope)
            try {
                withTimeout(EVENT_TIMEOUT_MS) { awaitEvent(events, "hello") }
                a.engine.revoke(requireNotNull(b.store.account()).deviceId)
                withTimeout(EVENT_TIMEOUT_MS) { awaitEvent(events, "revoked") }
            } finally {
                stream.stop()
                scope.cancel()
            }
            assertEquals(SyncResult.Revoked, b.engine.sync())
            assertEquals(null, b.store.account())
            assertEquals(listOf("alice"), labels(b))
            assertInstanceOf(SyncResult.Synced::class.java, a.engine.sync())
        }

    @Test
    fun `a phone whose clock is an hour off is corrected by stale_request for sign-up and sync`(): Unit =
        runBlocking {
            val a = phone { System.currentTimeMillis() / MILLIS + SKEW_S }
            a.store.add(otp("alice"))
            signUp(a, newEmail())
            a.store.add(otp("dave"))
            assertInstanceOf(SyncResult.Synced::class.java, a.engine.sync())
            val offset = requireNotNull(a.api()).clockOffset
            assertTrue(offset in (-SKEW_S - 5)..(-SKEW_S + 5), "offset $offset")
        }

    /**
     * Found by this test. `Login.verify` deletes the SRP session and checks the proof before
     * `register_device` checks the request timestamp, so on a stale clock the server answers
     * `stale_request` having already consumed the session; the client's one automatic retry then
     * meets `srp_failed`, which the app shows as "wrong password". A correct password on a phone
     * whose clock is more than 60 s off can never log in.
     */
    @Test
    fun `password login works on a phone whose clock is an hour off`(): Unit =
        runBlocking {
            val email = newEmail()
            signUp(phone(), email)
            val behind = phone { System.currentTimeMillis() / MILLIS - SKEW_S }
            logIn(behind, email)
            assertInstanceOf(SyncResult.Synced::class.java, behind.engine.sync())
        }

    @Test
    fun `an enrollment token works on a phone whose clock is an hour off`(): Unit =
        runBlocking {
            val a = phone()
            a.store.add(otp("alice"))
            signUp(a, newEmail())
            val c = phone { System.currentTimeMillis() / MILLIS - SKEW_S }
            val token = mintToken(requireNotNull(a.store.account()).accountId)
            c.engine.enrollWithPassword(url, token, PASSWORD, "Phone C")
            assertInstanceOf(SyncResult.Synced::class.java, c.engine.sync())
        }

    @Test
    fun `a wrong password is refused, five of them lock the account, and the answer is the contract's`(): Unit =
        runBlocking {
            val email = newEmail()
            signUp(phone(), email)
            val intruder = phone()
            repeat(LOCKOUT_THRESHOLD) {
                assertThrows<CryptoException.AuthenticationFailed> { runBlocking { logIn(intruder, email, "not the password") } }
            }
            val locked = assertThrows<Exception> { runBlocking { logIn(intruder, email) } }
            assertInstanceOf(AccountProblem.AccountLocked::class.java, AccountProblem.of(locked), locked.toString())
        }

    @Test
    fun `sign-up for an address that has an account is refused with email_taken`(): Unit =
        runBlocking {
            val email = newEmail()
            signUp(phone(), email)
            val second = phone()
            second.signup.requestCode(url, email)
            val draft = second.signup.prepare(PASSWORD)
            draft.confirmRecoverySaved()
            val error = assertThrows<Exception> { runBlocking { second.signup.create(url, email, "123456", draft, "Phone X") } }
            assertEquals(AccountProblem.EmailTaken, AccountProblem.of(error))
            assertEquals(null, second.store.account())
        }

    private suspend fun awaitEvent(
        events: Channel<ServerEvent>,
        type: String,
    ): ServerEvent {
        while (true) {
            val event = events.receive()
            if (event.type == type) return event
        }
    }

    /** The server's own CLI, in the same data directory (SQLite WAL allows a second process). */
    private fun mintToken(accountId: String): String {
        val serverDir = File(requireNotNull(System.getProperty("uotp.server.dir")))
        val process =
            ProcessBuilder("uv", "run", "--frozen", "--project", serverDir.path, "ultimateotp", "token-create", accountId)
                .apply {
                    environment().keys.removeIf { it.startsWith("UOTP_") }
                    environment()["UOTP_DATA_DIR"] = data.path
                    environment()["UOTP_MIGRATIONS_DIR"] = requireNotNull(System.getProperty("uotp.migrations.dir"))
                    environment()["UOTP_EMAIL_VERIFICATION"] = "disabled"
                    environment()["UOTP_LOG_LEVEL"] = "WARNING"
                }.start()
        val out = process.inputStream.bufferedReader().readText()
        check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) { "token-create failed: $out" }
        return Json
            .parseToJsonElement(out)
            .jsonObject
            .getValue("enrollment_token")
            .jsonPrimitive.content
    }

    private companion object {
        const val PASSWORD = "correct horse battery staple"
        const val STARTUP_S = 120L
        const val EVENT_TIMEOUT_MS = 15_000L
        const val SKEW_S = 3_600L
        const val LOCKOUT_THRESHOLD = 5
        const val LOG_TAIL = 4_000
        const val MILLIS = 1000L
    }
}
