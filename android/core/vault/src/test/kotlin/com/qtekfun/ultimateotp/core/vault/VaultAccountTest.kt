// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault

import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** What happens to the vault when it joins an account, is locked and unlocked, and leaves again. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VaultAccountTest {
    private val db =
        Room
            .inMemoryDatabaseBuilder<VaultDatabase>(ApplicationProvider.getApplicationContext<Context>())
            .setDriver(AndroidSQLiteDriver())
            .build()
    private val secrets = InMemorySecretStore(requiresUserAuthentication = true)
    private val vault = VaultRepository(db.dao(), secrets, clock = { 1_000L })
    private val account = AccountState(serverUrl = "https://otp.example.org", accountId = "acc_x", deviceId = "dev_x", label = "Pixel")

    @After
    fun close() = db.close()

    private fun labels() = runBlocking { vault.items.first() }.map { it.otp.label }

    @Test
    fun `joining an account re-keys pending items and the new key survives a lock`(): Unit =
        runBlocking {
            Sodium.init()
            vault.create()
            vault.add(OtpAuthUri.parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP"))
            val newKey = Sodium.random(32)
            vault.saveDeviceKeys(DeviceKeys.generate())
            vault.installVaultKey(newKey, 1, "acc_x", account)
            assertEquals(listOf("alice"), labels())
            assertEquals(account, vault.account())

            vault.lock()
            assertEquals(VaultState.LOCKED, vault.state.value)
            assertTrue(labels().isEmpty())
            vault.unlock()
            assertEquals(listOf("alice"), labels())
            assertNotNull(vault.deviceKeys())
            assertTrue(newKey.contentEquals(vault.vaultKey()))
        }

    @Test
    fun `leaving the account keeps every entry as a pending local one and forgets the device keys`(): Unit =
        runBlocking {
            Sodium.init()
            vault.create()
            vault.add(OtpAuthUri.parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP"))
            vault.saveDeviceKeys(DeviceKeys.generate())
            vault.installVaultKey(Sodium.random(32), 3, "acc_x", account)
            vault.add(OtpAuthUri.parse("otpauth://totp/Ex:bob?secret=JBSWY3DPEHPK3PXP"))

            vault.leaveAccount()
            assertNull(vault.account())
            assertFalse(secrets.contains(VaultRepository.DEVICE_KEYS))
            assertEquals(listOf("alice", "bob"), labels().sorted())
            assertTrue(vault.rows().all { it.dirty && !it.onServer })
            // And it is still a working vault after a lock.
            vault.lock()
            vault.unlock()
            assertEquals(listOf("alice", "bob"), labels().sorted())
        }

    @Test
    fun `a HOTP counter is stored before the code is shown and survives a lock`(): Unit =
        runBlocking {
            vault.create()
            val item = vault.add(OtpAuthUri.parse("otpauth://hotp/Ex:alice?secret=JBSWY3DPEHPK3PXP&counter=4"))
            assertEquals(5L, vault.nextHotpCounter(item.id)!!.otp.counter)
            assertEquals(6L, vault.nextHotpCounter(item.id)!!.otp.counter)
            vault.lock()
            vault.unlock()
            assertEquals(
                6L,
                vault.items
                    .first()
                    .single()
                    .otp.counter,
            )
            assertNull(vault.nextHotpCounter(java.util.UUID.randomUUID()))
        }

    @Test
    fun `import skips what is already there and snapshot lists live entries only`(): Unit =
        runBlocking {
            vault.create()
            val a = OtpAuthUri.parse("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&issuer=Ex")
            val b = OtpAuthUri.parse("otpauth://totp/Ex:bob?secret=JBSWY3DPEHPK3PXQ&issuer=Ex")
            assertEquals(ImportSummary(added = 2, duplicates = 0), vault.import(listOf(a, b)))
            assertEquals(ImportSummary(added = 0, duplicates = 2), vault.import(listOf(a, b)))
            val gone = vault.snapshot().first { it.otp.label == "bob" }
            vault.delete(gone.id)
            assertEquals(listOf("alice"), vault.snapshot(includeTrashed = false).map { it.otp.label })
        }
}
