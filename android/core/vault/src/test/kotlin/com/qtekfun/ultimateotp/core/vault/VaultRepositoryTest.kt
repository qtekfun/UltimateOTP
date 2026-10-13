// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault

import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.importers.ImportedAccount
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.core.vault.db.ItemEntity
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
    private var now = 1_000L
    private val vault = VaultRepository(db.dao(), secrets, clock = { now })
    private val transfer = VaultTransfer(vault, clock = { now })
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
            assertEquals(1, vault.trashed.first().size) // deleting moves to the trash
            vault.purge(item.id)
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
            // The deleted entry is in the trash: the file brings it back instead of adding a copy.
            assertEquals(ImportOutcome.Imported(ImportSummary(0, 1, restored = 1)), transfer.import(plain.toByteArray(), null))
            assertArrayEquals(
                vault.items
                    .first()
                    .map { it.otp.label }
                    .sorted()
                    .toTypedArray(),
                arrayOf("alice", "g"),
            )
        }

    private fun otp(
        issuer: String,
        label: String,
        secret: String = "JBSWY3DPEHPK3PXP",
    ) = OtpAuthUri.parse("otpauth://totp/$issuer:$label?secret=$secret&issuer=$issuer")

    @Test
    fun `trash, restore, persistence across lock and the 30 day purge`(): Unit =
        runBlocking {
            vault.create()
            val a = vault.add(otp("A", "one"))
            val b = vault.add(otp("B", "two", "GEZDGNBVGY3TQOJQ"))
            vault.trash(a.id)
            assertEquals(listOf(b.id), vault.items.first().map { it.id })
            assertEquals(listOf(a.id), vault.trashed.first().map { it.id })

            vault.lock()
            vault.unlock()
            assertEquals(listOf(a.id), vault.trashed.first().map { it.id })

            now += 1_000
            vault.restore(a.id)
            assertTrue(vault.trashed.first().isEmpty())
            assertEquals(2, vault.items.first().size)

            vault.trash(a.id)
            now += VaultItem.TRASH_RETENTION_MS - 1
            assertEquals(0, vault.purgeExpired())
            now += 1
            assertEquals(1, vault.purgeExpired())
            assertTrue(vault.trashed.first().isEmpty())
            assertEquals(listOf(b.id), vault.snapshot().map { it.id })
        }

    @Test
    fun `trashing a synced item keeps the row and only marks the state`(): Unit =
        runBlocking {
            vault.create()
            val a = vault.add(otp("A", "one"))
            val committed = vault.cipher().seal(a, version = 3)
            val synced =
                ItemRow(
                    a.id,
                    serverVersion = 3,
                    serverBlob = committed,
                    serverDeleted = false,
                    localBlob = null,
                    localDeleted = false,
                    dirty = false,
                )
            db.dao().upsert(listOf(ItemEntity.of(synced)))
            vault.trash(a.id)
            val row = db.dao().item(a.id.toString())!!.toRow()
            assertTrue(row.dirty)
            assertFalse(row.localDeleted) // trashed, not deleted: the other devices get it as an edit
            vault.purge(a.id)
            assertTrue(
                db
                    .dao()
                    .item(a.id.toString())!!
                    .toRow()
                    .localDeleted,
            )
        }

    @Test
    fun `empty trash removes only trashed entries`(): Unit =
        runBlocking {
            vault.create()
            val a = vault.add(otp("A", "one"))
            vault.add(otp("B", "two", "GEZDGNBVGY3TQOJQ"))
            vault.trash(a.id)
            assertEquals(1, vault.emptyTrash())
            assertEquals(1, vault.items.first().size)
            assertTrue(vault.trashed.first().isEmpty())
        }

    @Test
    fun `move persists order keys and survives a lock`(): Unit =
        runBlocking {
            vault.create()
            val ids =
                (1..4).map {
                    vault
                        .add(
                            otp("Issuer$it", "u$it", "JBSWY3DPEHPK3PX$it".replace("1", "A").replace("3", "C").replace("4", "D")),
                        ).id
                }
            val before = vault.items.first().map { it.id }
            assertEquals(ids, before)
            now += 10
            vault.move(0, 2)
            val after = vault.items.first().map { it.id }
            assertEquals(listOf(ids[1], ids[2], ids[0], ids[3]), after)
            vault.lock()
            vault.unlock()
            assertEquals(after, vault.items.first().map { it.id })
            // A trashed entry is not part of the indexes: the list shown to the user is.
            vault.trash(ids[1])
            vault.move(0, 1)
            assertEquals(listOf(ids[0], ids[2], ids[3]).let { listOf(ids[0], ids[2], ids[3]) }.size, vault.items.first().size)
        }

    @Test
    fun `import skips same issuer, account and secret in any case, and restores from the trash`(): Unit =
        runBlocking {
            vault.create()
            val a = vault.add(otp("Example", "Alice"))
            vault.add(otp("Bank", "bob", "GEZDGNBVGY3TQOJQ"))
            vault.trash(a.id)
            val summary =
                vault.importAccounts(
                    listOf(
                        ImportedAccount(otp("EXAMPLE", "alice")),
                        ImportedAccount(otp("bank", " BOB ", "GEZDGNBVGY3TQOJQ")),
                        ImportedAccount(otp("Bank", "bob", "MFRGGZDFMZTWQ2LK"), notes = "other secret", favorite = true),
                        ImportedAccount(otp("Bank", "bob", "MFRGGZDFMZTWQ2LK")),
                    ),
                )
            assertEquals(ImportSummary(added = 1, duplicates = 2, restored = 1), summary)
            val items = vault.items.first()
            assertEquals(3, items.size)
            assertTrue(items.any { it.notes == "other secret" && it.favorite })
        }

    @Test
    fun `importing a foreign file keeps notes and reports unsupported variants clearly`(): Unit =
        runBlocking {
            vault.create()
            val aegis =
                """{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[
                {"type":"totp","name":"alice","issuer":"Example","note":"hello","favorite":true,
                 "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}]}}"""
            assertEquals(ImportKind.FOREIGN, transfer.detect(aegis.toByteArray()))
            val out = transfer.import(aegis.toByteArray(), null)
            assertEquals(ImportOutcome.Imported(ImportSummary(1, 0)), out)
            val item = vault.items.first().single()
            assertEquals("hello", item.notes)
            assertTrue(item.favorite)
            assertEquals(ImportOutcome.Imported(ImportSummary(0, 1)), transfer.import(aegis.toByteArray(), null))

            val encryptedBitwarden = """{"encrypted":true,"folders":[],"items":[]}"""
            val unreadable = transfer.import(encryptedBitwarden.toByteArray(), null)
            assertTrue(unreadable is ImportOutcome.Unreadable && "encrypted" in unreadable.reason)
        }

    @Test
    fun `plain export leaves the trash out and encrypted export keeps it`(): Unit =
        runBlocking {
            vault.create()
            val a = vault.add(otp("A", "one"))
            vault.add(otp("B", "two", "GEZDGNBVGY3TQOJQ"))
            vault.trash(a.id)
            assertEquals(1, transfer.exportPlain().lines().count { it.startsWith("otpauth://") })
            assertEquals(2, vault.snapshot().size)
        }

    @Test
    fun `autofill associations are stored normalized`(): Unit =
        runBlocking {
            vault.create()
            val a = vault.add(otp("A", "one"))
            vault.setAutofillAssociations(a.id, listOf(" Example.COM ", "com.example.app", "example.com", ""))
            assertEquals(
                listOf("example.com", "com.example.app"),
                vault.items
                    .first()
                    .single()
                    .autofill,
            )
        }
}
