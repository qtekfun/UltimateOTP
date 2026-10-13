// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault

import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import com.qtekfun.ultimateotp.core.vault.secure.InMemorySecretStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VaultRepositoryTest {
    private val db =
        Room
            .inMemoryDatabaseBuilder<VaultDatabase>(ApplicationProvider.getApplicationContext<Context>())
            .setDriver(AndroidSQLiteDriver())
            .build()
    private val secrets = InMemorySecretStore(requiresUserAuthentication = true)
    private val vault = VaultRepository(db.dao(), secrets, clock = { 1_000L })
    private val transfer = VaultTransfer(vault, clock = { 1_000L })
    private val cheap = listOf(2L to (16L shl 20))

    @After
    fun close() = db.close()

    private val uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"

    @Test
    fun `create, add, lock, unlock with authentication`(): Unit =
        runBlocking {
            assertEquals(VaultState.NONE, vault.state.value)
            vault.create()
            vault.add(OtpAuthUri.parse(uri))
            assertEquals(1, vault.items.first().size)
            // Only ciphertext reaches the database.
            val stored = db.dao().items().single()
            val blob = String(requireNotNull(stored.localBlob), Charsets.ISO_8859_1)
            assertFalse(blob.contains("JBSWY3DPEHPK3PXP"))
            assertFalse(blob.contains("Example"))

            vault.lock()
            assertEquals(VaultState.LOCKED, vault.state.value)
            assertTrue(vault.items.first().isEmpty())
            secrets.authenticated = false
            assertTrue(runCatching { vault.unlock() }.exceptionOrNull() is AuthenticationRequiredException)
            secrets.authenticated = true
            vault.unlock()
            assertEquals(
                "alice",
                vault.items
                    .first()
                    .single()
                    .otp.label,
            )
        }

    @Test
    fun `edit, HOTP counter and delete`(): Unit =
        runBlocking {
            vault.create()
            val item = vault.add(OtpAuthUri.parse("otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&counter=5"))
            vault.update(item.copy(notes = "work", favorite = true))
            assertEquals(6L, vault.nextHotpCounter(item.id)!!.otp.counter)
            val now = vault.items.first().single()
            assertEquals("work", now.notes)
            assertEquals(6L, now.otp.counter)
            vault.delete(item.id)
            assertTrue(vault.items.first().isEmpty())
            assertTrue(db.dao().items().isEmpty()) // never synced: removed, no tombstone
        }

    @Test
    fun `encrypted export round-trips and import skips duplicates`(): Unit =
        runBlocking {
            vault.create()
            vault.add(OtpAuthUri.parse(uri))
            vault.add(OtpAuthUri.parse("otpauth://steam/Steam:g?secret=JBSWY3DPEHPK3PXQ"))
            val file = transfer.exportEncrypted("pw", cheap)
            assertEquals(ImportOutcome.PasswordRequired(ImportKind.UOTP_EXPORT), transfer.import(file, null))
            assertEquals(ImportOutcome.WrongPassword, transfer.import(file, "nope"))
            assertEquals(ImportOutcome.Imported(ImportSummary(0, 2)), transfer.import(file, "pw"))

            val plain = transfer.exportPlain()
            vault.delete(
                vault.items
                    .first()
                    .first { it.otp.type == OtpType.STEAM }
                    .id,
            )
            assertEquals(ImportOutcome.Imported(ImportSummary(1, 1)), transfer.import(plain.toByteArray(), null))
            assertArrayEquals(
                vault.items
                    .first()
                    .map { it.otp.label }
                    .sorted()
                    .toTypedArray(),
                arrayOf("alice", "g"),
            )
        }
}
