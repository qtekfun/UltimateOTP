// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.FakeUotpServer
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import com.qtekfun.ultimateotp.core.sync.model.Merge
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SyncEngineTest {
    private val server = FakeUotpServer()
    private val http = OkHttpClient()
    private val cheap = { listOf(2L to (16L shl 20)) }

    @AfterEach
    fun close() = server.close()

    private class Device(
        val store: InMemorySyncStore,
        val engine: SyncEngine,
    )

    private fun device(clock: () -> Long = { 1_000L }): Device {
        val store = InMemorySyncStore(clock)
        return Device(store, SyncEngine(store, { UotpApi(it, http, nowSeconds = { server.now }) }, kdfLadder = cheap))
    }

    private fun otp(label: String) = OtpAuthUri.parse("otpauth://totp/Ex:$label?secret=JBSWY3DPEHPK3PXP")

    private fun bootstrapped(): Device =
        runBlocking {
            val a = device()
            a.store.add(otp("alice"))
            val words = a.engine.bootstrap(server.url, server.issueToken(), "correct horse", "Phone A")
            assertEquals(24, words.size)
            assertInstanceOf(SyncResult.Synced::class.java, a.engine.sync())
            a
        }

    @Test
    fun `bootstrap uploads the offline vault, password enrollment brings it to a new device`(): Unit =
        runBlocking {
            val a = bootstrapped()
            assertEquals(1L, server.state.head.version)
            val b = device()
            b.store.add(otp("bob")) // B had its own offline items: they are merged into the account
            b.engine.enrollWithPassword(server.url, server.issueToken(), "correct horse", "Phone B")
            assertInstanceOf(SyncResult.Synced::class.java, b.engine.sync())
            assertEquals(listOf("alice", "bob"), b.store.items().map { it.otp.label })
            // B enrolled itself: A refuses its heads until the user confirms B on A (crypto-format.md §5.2).
            assertInstanceOf(SyncResult.Rejected::class.java, a.engine.sync())
            val viewB = a.engine.devices().single { it.deviceId == b.store.account()!!.deviceId }
            assertTrue(!viewB.trusted)
            a.engine.trustDevice(viewB.deviceId)
            a.engine.sync()
            assertEquals(listOf("alice", "bob"), a.store.items().map { it.otp.label })
        }

    @Test
    fun `email code and SRP login from anywhere, like Ente`(): Unit =
        runBlocking {
            val a = bootstrapped()
            val b = device()
            val login = SrpEmailLogin(b.engine, { UotpApi(it, http, nowSeconds = { server.now }) })
            val (ticket, _) = login.requestCode(server.url, server.email)
            assertTrue(ticket.codeRequired)
            assertThrows<ApiException> { runBlocking { login.verifyCode(ticket, "000000") } }
            login.requestCode(server.url, server.email)
            login.verifyCode(ticket, server.lastEmailCode!!)
            assertThrows<com.qtekfun.ultimateotp.core.crypto.CryptoException.AuthenticationFailed> {
                runBlocking { login.complete(ticket, "wrong password", "B") }
            }
            login.requestCode(server.url, server.email)
            login.verifyCode(ticket, server.lastEmailCode!!)
            login.complete(ticket, "correct horse", "Phone B")
            assertInstanceOf(SyncResult.Synced::class.java, b.engine.sync())
            assertEquals(listOf("alice"), b.store.items().map { it.otp.label })
            assertEquals(2, b.engine.sessions().size)
            a.engine.sync()
        }

    @Test
    fun `recovery words, then a new password that works for SRP login`(): Unit =
        runBlocking {
            val a = device()
            a.store.add(otp("alice"))
            val words = a.engine.bootstrap(server.url, server.issueToken(), "forgotten", "A")
            a.engine.sync()
            val b = device()
            b.engine.enrollWithRecoveryKey(server.url, server.issueToken(), words.joinToString(" "), "B")
            b.engine.changePassword("brand new pass", currentPassword = null, recoveryWords = words.joinToString(" "))
            b.engine.sync()
            val c = device()
            val login = SrpEmailLogin(c.engine, { UotpApi(it, http, nowSeconds = { server.now }) })
            val (ticket, _) = login.requestCode(server.url, server.email)
            login.verifyCode(ticket, server.lastEmailCode!!)
            login.complete(ticket, "brand new pass", "C")
            c.engine.sync()
            assertEquals(listOf("alice"), c.store.items().map { it.otp.label })
        }

    @Test
    fun `wrong password and recovery key enrollment`(): Unit =
        runBlocking {
            bootstrapped()
            val b = device()
            assertThrows<com.qtekfun.ultimateotp.core.crypto.CryptoException.AuthenticationFailed> {
                b.engine.enrollWithPassword(server.url, server.issueToken(), "wrong", "B")
            }
        }

    @Test
    fun `pairing with matching words, then live edits flow both ways`(): Unit =
        runBlocking {
            val a = bootstrapped()
            val b = device()
            val link = a.engine.startPairing()
            val parsed = PairLink.parse(link.format())!!
            val joined = b.engine.joinPairing(parsed, "Phone B")
            val (candidate, wordsOnA) = a.engine.pairingCandidate(link.pairingId)!!
            assertEquals(joined.sasWords, wordsOnA)
            val waiting = async { b.engine.awaitPairing(joined, "Phone B", pollMillis = 10) }
            a.engine.approvePairing(link.pairingId, candidate)
            assertTrue(waiting.await())
            b.engine.sync()
            assertEquals(listOf("alice"), b.store.items().map { it.otp.label })

            val item = b.store.items().single()
            b.store.update(item.copy(notes = "from B"))
            b.engine.sync()
            a.engine.sync()
            assertEquals(
                "from B",
                a.store
                    .items()
                    .single()
                    .notes,
            )
            a.store.delete(item.id)
            a.engine.sync()
            b.engine.sync()
            assertTrue(b.store.items().isEmpty())
        }

    @Test
    fun `concurrent edits get a 409, merge and keep a conflict copy`(): Unit =
        runBlocking {
            var t = 1_000L
            val a = bootstrapped()
            val b = device { t }
            b.engine.enrollWithPassword(server.url, server.issueToken(), "correct horse", "B")
            b.engine.sync()
            a.engine.devices()
            a.engine.trustDevice(b.store.account()!!.deviceId)
            val item = a.store.items().single()
            a.store.update(item.copy(otp = item.otp.copy(label = "edited on A")))
            t = 5_000L
            b.store.update(
                b.store
                    .items()
                    .single()
                    .copy(otp = item.otp.copy(label = "edited on B")),
            )
            a.engine.sync()
            val result = b.engine.sync() as SyncResult.Synced
            assertEquals(1, result.conflicts)
            a.engine.sync()
            val labels = a.store.items().map { it.otp.label }
            assertEquals(listOf("edited on A", "edited on B"), labels.sorted())
            assertTrue(
                a.store
                    .items()
                    .first { it.otp.label == "edited on A" }
                    .otp.tags
                    .contains(Merge.CONFLICT_TAG),
            )
        }

    @Test
    fun `a restored old server state is refused as a rollback, then re-seeded on request`(): Unit =
        runBlocking {
            val a = bootstrapped()
            val old = server.state
            a.store.add(otp("carol"))
            a.engine.sync()
            server.state = old
            val rejected = a.engine.sync()
            assertInstanceOf(SyncResult.Rejected::class.java, rejected)
            assertEquals(2, a.store.items().size) // nothing lost locally
            assertInstanceOf(SyncResult.Synced::class.java, a.engine.uploadLocalCopy())
            assertEquals(
                2,
                server.state.items.values
                    .count { !it.deleted },
            )
        }

    @Test
    fun `a head whose manifest does not match the items is refused`(): Unit =
        runBlocking {
            val a = bootstrapped()
            val b = device()
            b.engine.enrollWithPassword(server.url, server.issueToken(), "correct horse", "B")
            val s = server.state
            val (id, item) = s.items.entries.first()
            // The server swaps a blob but keeps the signed head: the manifest no longer matches.
            server.state = s.copy(items = s.items + (id to item.copy(blob = item.blob!!.reversed())))
            assertInstanceOf(SyncResult.Rejected::class.java, b.engine.sync())
            a.engine.sync()
        }

    @Test
    fun `clock skew is corrected from stale_request`(): Unit =
        runBlocking {
            val a = bootstrapped()
            server.now += 3_600
            a.store.add(otp("dave"))
            assertInstanceOf(SyncResult.Synced::class.java, a.engine.sync())
        }

    @Test
    fun `revoked device leaves the account, rotation keeps the others`(): Unit =
        runBlocking {
            val a = bootstrapped()
            val b = device()
            b.engine.enrollWithPassword(server.url, server.issueToken(), "correct horse", "B")
            b.engine.sync()
            a.engine.trustDevice(b.store.account()!!.deviceId)
            val c = device()
            c.engine.enrollWithPassword(server.url, server.issueToken(), "correct horse", "C")
            c.engine.sync()
            val oldEpoch = a.store.account()!!.keyEpoch
            a.engine.revoke(c.store.account()!!.deviceId)
            assertEquals(SyncResult.Revoked, c.engine.sync())
            assertEquals(listOf("alice"), c.store.items().map { it.otp.label }) // kept locally
            assertInstanceOf(SyncResult.Synced::class.java, a.engine.rotate("correct horse", null))
            assertNotEquals(oldEpoch, a.store.account()!!.keyEpoch)
            assertInstanceOf(SyncResult.Synced::class.java, b.engine.sync())
            assertEquals(a.store.account()!!.keyEpoch, b.store.account()!!.keyEpoch)
            assertEquals(listOf("alice"), b.store.items().map { it.otp.label })
        }

    @Test
    fun `enrollment links and LAN policy`() {
        val e = EnrollLink.parse("uotp://enroll?server=https%3A%2F%2Fotp.example&token=uoe_x")!!
        assertEquals("https://otp.example", e.server)
        assertEquals(EnrollmentPolicy.Choice.Refused, EnrollmentPolicy.choose("https://otp.example.com", "", allowRemote = false))
        assertEquals(EnrollmentPolicy.Choice.Use("http://192.168.1.5:8080"), EnrollmentPolicy.choose("http://192.168.1.5:8080", "", false))
        assertEquals(
            EnrollmentPolicy.Choice.Use("http://10.0.0.2"),
            EnrollmentPolicy.choose("https://otp.example.com", "http://10.0.0.2", false),
        )
        assertTrue(EnrollmentPolicy.isLocal("http://100.101.1.1"))
        assertEquals(null, PairLink.parse("uotp://pair?v=2&s=x&p=y&k=z&a=w"))
    }

    @Test
    fun `api errors carry the problem code`(): Unit =
        runBlocking {
            val api = UotpApi(server.url, http, nowSeconds = { server.now })
            val e = assertThrows<ApiException> { runBlocking { api.recoveryKeys("uoe_unknown") } }
            assertEquals("invalid_token", e.code)
            assertEquals("1.0.0", api.serverInfo().apiVersion)
        }
}
