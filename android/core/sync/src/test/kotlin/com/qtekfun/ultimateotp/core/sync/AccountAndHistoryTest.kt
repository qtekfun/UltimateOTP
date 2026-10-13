// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.account.AccountAction
import com.qtekfun.ultimateotp.core.sync.account.AccountActionResult
import com.qtekfun.ultimateotp.core.sync.account.AccountActionState
import com.qtekfun.ultimateotp.core.sync.account.AccountActions
import com.qtekfun.ultimateotp.core.sync.account.AccountManagement
import com.qtekfun.ultimateotp.core.sync.account.ReauthProof
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.FakeUotpServer
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.core.sync.history.HistoryRecovery
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Contract 1.2.0 on the fake server: account management and version history. */
class AccountAndHistoryTest {
    private val server = FakeUotpServer()
    private val http = OkHttpClient()
    private val cheap = { listOf(2L to (16L shl 20)) }
    private val password = "correct horse"

    @AfterEach
    fun close() = server.close()

    private class Device(
        val store: InMemorySyncStore,
        val engine: SyncEngine,
    )

    private fun apiFor(): (String) -> UotpApi = { UotpApi(it, http, nowSeconds = { server.now }) }

    private fun device(): Device {
        val store = InMemorySyncStore { 1_000L }
        return Device(store, SyncEngine(store, apiFor(), kdfLadder = cheap))
    }

    private fun otp(label: String) = OtpAuthUri.parse("otpauth://totp/Ex:$label?secret=JBSWY3DPEHPK3PXP")

    private fun management(d: Device) = AccountManagement(d.store, d.engine, apiFor())

    private fun recovery(
        d: Device,
        clock: () -> Long = { 5_000L },
    ) = HistoryRecovery(d.store, d.engine, apiFor(), clock)

    private fun single(): Device =
        runBlocking {
            val a = device()
            a.store.add(otp("alice"))
            a.engine.bootstrap(server.url, server.issueToken(), password, "Phone A")
            a.engine.sync()
            a
        }

    /** Two devices of the account, B trusted by A. */
    private fun pair(): Pair<Device, Device> =
        runBlocking {
            val a = single()
            val b = device()
            b.engine.enrollWithPassword(server.url, server.issueToken(), password, "Phone B")
            b.engine.sync()
            a.engine.trustDevice(b.store.account()!!.deviceId)
            a.engine.sync()
            a to b
        }

    // ---- account management ---------------------------------------------------------------------

    @Test
    fun `delete account with the password, the entries stay on the device`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.DELETE_ACCOUNT)
            actions.deleteAccount(ReauthProof.Password(password))
            val done = assertInstanceOf(AccountActionState.Done::class.java, actions.state.value)
            val result = assertInstanceOf(AccountActionResult.AccountDeleted::class.java, done.result)
            assertEquals(1, result.removed.devices)
            assertTrue(server.accountDeleted)
            assertNull(a.store.account())
            assertEquals(listOf("alice"), a.store.items().map { it.otp.label })
        }

    @Test
    fun `a wrong password changes nothing and the flow stays on the confirmation`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.DELETE_ACCOUNT)
            actions.deleteAccount(ReauthProof.Password("not the password"))
            val state = assertInstanceOf(AccountActionState.Confirming::class.java, actions.state.value)
            assertEquals(AccountProblem.WrongPassword, state.problem)
            assertFalse(server.accountDeleted)
            assertNotNull(a.store.account())
        }

    @Test
    fun `delete with an emailed code, wrong code first`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.DELETE_ACCOUNT)
            actions.requestEmailCode()
            assertInstanceOf(AccountActionState.AwaitingEmailCode::class.java, actions.state.value)
            actions.deleteAccount(ReauthProof.EmailCode("000000"))
            val retry = assertInstanceOf(AccountActionState.AwaitingEmailCode::class.java, actions.state.value)
            assertEquals(AccountProblem.InvalidCode, retry.problem)
            assertFalse(server.accountDeleted)
            actions.deleteAccount(ReauthProof.EmailCode(server.lastEmailCode!!))
            assertInstanceOf(AccountActionState.Done::class.java, actions.state.value)
            assertTrue(server.accountDeleted)
        }

    @Test
    fun `no action is sent without its confirmation step`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            assertThrows<IllegalStateException> { runBlocking { actions.deleteAccount(ReauthProof.Password(password)) } }
            actions.begin(AccountAction.EXPORT)
            assertThrows<IllegalStateException> { runBlocking { actions.deleteAccount(ReauthProof.Password(password)) } }
            assertThrows<IllegalStateException> { runBlocking { actions.signOutOthers(password) } }
            assertEquals(0, server.requests("/otp/v1/account/delete"))
            assertEquals(0, server.requests("/otp/v1/devices/revoke-others"))
            actions.cancel()
            assertEquals(AccountActionState.Idle, actions.state.value)
        }

    @Test
    fun `server problems become problem states and leave everything as it was`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.DELETE_ACCOUNT)
            server.failNext("/otp/v1/account/reauth/srp", 429, "client_blocked", retryAfter = 900)
            actions.deleteAccount(ReauthProof.Password(password))
            assertEquals(AccountProblem.RateLimited(900), (actions.state.value as AccountActionState.Confirming).problem)
            server.failNext("/otp/v1/account/delete", 500, "internal_error")
            actions.deleteAccount(ReauthProof.Password(password))
            assertEquals(AccountProblem.Server("internal_error"), (actions.state.value as AccountActionState.Confirming).problem)
            assertFalse(server.accountDeleted)
            assertNotNull(a.store.account())
            // The same flow then succeeds.
            actions.deleteAccount(ReauthProof.Password(password))
            assertTrue(server.accountDeleted)
        }

    @Test
    fun `change email needs a proof and a code from the new address`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.CHANGE_EMAIL)
            actions.changeEmail("New.Owner@example.net", ReauthProof.Password(password))
            val waiting = assertInstanceOf(AccountActionState.AwaitingNewAddressCode::class.java, actions.state.value)
            assertEquals("new.owner@example.net", waiting.newEmail)
            assertEquals("owner@example.com", server.email) // not switched yet
            actions.confirmEmailChange("111111")
            assertEquals(AccountProblem.InvalidCode, (actions.state.value as AccountActionState.AwaitingNewAddressCode).problem)
            actions.confirmEmailChange(server.lastEmailCode!!)
            val done = assertInstanceOf(AccountActionState.Done::class.java, actions.state.value)
            assertEquals(AccountActionResult.EmailChanged("new.owner@example.net"), done.result)
            assertEquals("new.owner@example.net", server.email)
        }

    @Test
    fun `sign out everywhere else revokes and rotates, and checks the password first`(): Unit =
        runBlocking {
            val (a, b) = pair()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.SIGN_OUT_OTHERS)
            actions.signOutOthers(password = "wrong")
            assertEquals(AccountProblem.WrongPassword, (actions.state.value as AccountActionState.Confirming).problem)
            assertEquals(2, a.engine.devices().count { !it.revoked }) // nothing was revoked

            actions.signOutOthers(password = password)
            val done = assertInstanceOf(AccountActionState.Done::class.java, actions.state.value)
            assertEquals(AccountActionResult.SignedOutOthers(revoked = 1, rotated = true), done.result)
            assertEquals(1, a.engine.devices().count { !it.revoked })
            assertEquals(2L, a.store.account()!!.keyEpoch)
            assertEquals(SyncResult.Revoked, b.engine.sync())
        }

    @Test
    fun `sign out everywhere else without a password still signs out and says rotation is pending`(): Unit =
        runBlocking {
            val (a, _) = pair()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.SIGN_OUT_OTHERS)
            actions.signOutOthers()
            val done = assertInstanceOf(AccountActionState.Done::class.java, actions.state.value)
            assertEquals(AccountActionResult.SignedOutOthers(revoked = 1, rotated = false), done.result)
            a.engine.sync()
            assertTrue(a.store.account()!!.rotationRequired)
        }

    @Test
    fun `export returns the server document and holds no plaintext`(): Unit =
        runBlocking {
            val a = single()
            val actions = AccountActions(management(a))
            actions.begin(AccountAction.EXPORT)
            actions.export()
            val json = ((actions.state.value as AccountActionState.Done).result as AccountActionResult.Exported).json
            assertTrue("ultimateotp-server-export-1" in json)
            assertFalse("alice" in json)
            assertFalse("JBSWY3DPEHPK3PXP" in json)
        }

    // ---- history and trash ------------------------------------------------------------------------

    @Test
    fun `an entry removed for good comes back from the server trash on every device`(): Unit =
        runBlocking {
            val (a, b) = pair()
            val id =
                a.store
                    .items()
                    .single()
                    .id
            a.store.delete(id)
            a.engine.sync()
            b.engine.sync()
            assertTrue(b.store.items().isEmpty())

            val history = recovery(a)
            val entries = history.deletedEntries()
            assertEquals(listOf(id), entries.map { it.item.id })
            assertEquals(
                "alice",
                entries
                    .single()
                    .item.otp.label,
            )
            assertTrue(history.restoreDeleted(id))
            assertEquals(listOf("alice"), a.store.items().map { it.otp.label })
            b.engine.sync()
            assertEquals(listOf("alice"), b.store.items().map { it.otp.label })
            assertTrue(history.deletedEntries().isEmpty())
            assertFalse(history.restoreDeleted(id))
        }

    @Test
    fun `an older version of an entry can be restored as a new edit`(): Unit =
        runBlocking {
            val a = single()
            val original = a.store.items().single()
            a.store.update(original.copy(notes = "second"))
            a.engine.sync()
            a.store.update(
                a.store
                    .items()
                    .single()
                    .copy(notes = "third"),
            )
            a.engine.sync()
            val history = recovery(a)
            val versions = history.versions()
            assertEquals(listOf(3L, 2L, 1L), versions.map { it.version })
            assertEquals("", history.itemAt(1, original.id)!!.notes)
            assertEquals("second", history.itemAt(2, original.id)!!.notes)
            assertTrue(history.restoreVersion(2, original.id))
            assertEquals(
                "second",
                a.store
                    .items()
                    .single()
                    .notes,
            )
            assertNull(history.itemAt(3, java.util.UUID.randomUUID()))
        }

    @Test
    fun `restoring an old version keeps today's trash state and position`(): Unit =
        runBlocking {
            val a = single()
            val item = a.store.items().single()
            a.store.update(item.copy(notes = "v2"))
            a.engine.sync()
            a.store.put(
                a.store
                    .items()
                    .single()
                    .copy(trashed = true, trashChanged = 4_000, order = "V", orderChanged = 4_000),
            )
            a.engine.sync()
            assertTrue(recovery(a).restoreVersion(1, item.id))
            val now = a.store.items().single()
            assertEquals("", now.notes)
            assertTrue(now.trashed)
            assertEquals("V", now.order)
        }

    @Test
    fun `an aged out version is reported by its code and rotation restarts the history`(): Unit =
        runBlocking {
            val a = single()
            val item = a.store.items().single()
            a.store.update(item.copy(notes = "second"))
            a.engine.sync()
            server.pruneHistoryBefore(1)
            val history = recovery(a)
            val e = assertThrows<ApiException> { runBlocking { history.itemAt(1, item.id) } }
            assertEquals("history_pruned", e.code)
            assertEquals(410, e.status)
            assertEquals("second", history.itemAt(2, item.id)!!.notes)

            a.engine.rotate(password, null)
            assertEquals(listOf(3L), history.versions().map { it.version })
        }

    @Test
    fun `a full answer drops local entries that the server no longer lists`(): Unit =
        runBlocking {
            val (a, b) = pair()
            val id =
                a.store
                    .items()
                    .single()
                    .id
            assertEquals(1, b.store.items().size)
            a.store.delete(id)
            a.engine.sync()
            server.compactTombstones() // the tombstone is gone: b would never learn of the deletion
            b.engine.sync()
            assertTrue(b.store.items().isEmpty())
            assertEquals(a.store.account()!!.acceptedVersion, b.store.account()!!.acceptedVersion)
        }
}
