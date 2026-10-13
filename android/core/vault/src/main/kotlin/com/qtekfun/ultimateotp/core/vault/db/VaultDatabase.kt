// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault.db

import android.content.Context
import androidx.room3.Dao
import androidx.room3.Database
import androidx.room3.Entity
import androidx.room3.Insert
import androidx.room3.OnConflictStrategy
import androidx.room3.PrimaryKey
import androidx.room3.Query
import androidx.room3.Room
import androidx.room3.RoomDatabase
import androidx.room3.Transaction
import androidx.sqlite.driver.AndroidSQLiteDriver
import com.qtekfun.ultimateotp.core.sync.model.ItemRow
import kotlinx.coroutines.flow.Flow
import java.util.UUID

/** An item row ([ItemRow]): ciphertext only, never plaintext. */
@Entity(tableName = "item")
class ItemEntity(
    @PrimaryKey val id: String,
    val serverVersion: Long,
    val serverBlob: ByteArray?,
    val serverDeleted: Boolean,
    val localBlob: ByteArray?,
    val localDeleted: Boolean,
    val dirty: Boolean,
) {
    fun toRow() = ItemRow(UUID.fromString(id), serverVersion, serverBlob, serverDeleted, localBlob, localDeleted, dirty)

    companion object {
        fun of(row: ItemRow) =
            ItemEntity(
                row.id.toString(),
                row.serverVersion,
                row.serverBlob,
                row.serverDeleted,
                row.localBlob,
                row.localDeleted,
                row.dirty,
            )
    }
}

/** Non-secret vault metadata (account id, accepted version, pinned devices...) as JSON values. */
@Entity(tableName = "meta")
class MetaEntity(
    @PrimaryKey val key: String,
    val value: String,
)

@Dao
interface VaultDao {
    @Query("SELECT * FROM item")
    fun observeItems(): Flow<List<ItemEntity>>

    @Query("SELECT * FROM item")
    suspend fun items(): List<ItemEntity>

    @Query("SELECT * FROM item WHERE id = :id")
    suspend fun item(id: String): ItemEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(items: List<ItemEntity>)

    @Query("DELETE FROM item WHERE id IN (:ids)")
    suspend fun delete(ids: List<String>)

    @Query("DELETE FROM item")
    suspend fun deleteAllItems()

    @Query("SELECT value FROM meta WHERE `key` = :key")
    suspend fun meta(key: String): String?

    @Query("SELECT value FROM meta WHERE `key` = :key")
    fun observeMeta(key: String): Flow<String?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putMeta(meta: MetaEntity)

    @Query("DELETE FROM meta WHERE `key` = :key")
    suspend fun deleteMeta(key: String)

    /** Applies one sync or edit step atomically. */
    @Transaction
    suspend fun apply(
        upserts: List<ItemEntity>,
        deletes: List<String>,
        meta: List<MetaEntity>,
    ) {
        if (upserts.isNotEmpty()) upsert(upserts)
        if (deletes.isNotEmpty()) delete(deletes)
        meta.forEach { putMeta(it) }
    }
}

@Database(entities = [ItemEntity::class, MetaEntity::class], version = VaultDatabase.VERSION, exportSchema = true)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun dao(): VaultDao

    companion object {
        const val VERSION = 1
        const val FILE_NAME = "vault.db"

        fun create(context: Context): VaultDatabase =
            Room
                .databaseBuilder<VaultDatabase>(context.applicationContext, FILE_NAME)
                .setDriver(AndroidSQLiteDriver())
                .build()
    }
}
