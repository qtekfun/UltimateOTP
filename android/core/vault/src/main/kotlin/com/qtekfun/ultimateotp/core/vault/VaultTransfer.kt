// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.crypto.EnteExport
import com.qtekfun.ultimateotp.core.crypto.ExportFile
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.importers.ForeignFormat
import com.qtekfun.ultimateotp.core.importers.ForeignImport
import com.qtekfun.ultimateotp.core.importers.ImportParse
import com.qtekfun.ultimateotp.core.importers.ImportedAccount
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.otp.PlainListImport
import com.qtekfun.ultimateotp.core.sync.model.ItemCodec
import com.qtekfun.ultimateotp.core.sync.model.ItemFormatException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.util.UUID

/**
 * What a file is, before asking the user anything. [FOREIGN] is another authenticator's export
 * (Aegis, 2FAS, andOTP, Raivo, Bitwarden, Proton).
 */
enum class ImportKind { UOTP_EXPORT, ENTE_ENCRYPTED, PLAIN_LIST, FOREIGN }

sealed interface ImportOutcome {
    data class Imported(
        val summary: ImportSummary,
    ) : ImportOutcome

    data class PasswordRequired(
        val kind: ImportKind,
        /** Which app's file, for [ImportKind.FOREIGN]. */
        val source: ForeignFormat? = null,
    ) : ImportOutcome

    data object WrongPassword : ImportOutcome

    data object Unsupported : ImportOutcome

    /** A file of an unsupported variant or one that is damaged; [reason] is a fixed text without file content. */
    data class Unreadable(
        val format: ForeignFormat?,
        val reason: String,
    ) : ImportOutcome
}

/** Encrypted and plain export, and import of our own, Ente's and plain URI-list files. */
class VaultTransfer(
    private val vault: VaultRepository,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    fun detect(bytes: ByteArray): ImportKind =
        when {
            ExportFile.isExport(bytes) -> ImportKind.UOTP_EXPORT
            EnteExport.isEncryptedExport(String(bytes, Charsets.UTF_8)) -> ImportKind.ENTE_ENCRYPTED
            ForeignImport.detect(bytes) != null -> ImportKind.FOREIGN
            else -> ImportKind.PLAIN_LIST
        }

    /** `.uotp` file of every item (crypto-format.md §10). [ladder] from [PasswordKdf.ladderFor]. */
    suspend fun exportEncrypted(
        password: String,
        ladder: List<Pair<Long, Long>>,
    ): ByteArray {
        val items = vault.snapshot().map { Json.parseToJsonElement(String(ItemCodec.encode(it))) }
        val doc =
            JsonObject(
                mapOf(
                    "format" to JsonPrimitive("uotp-export"),
                    "version" to JsonPrimitive(1),
                    "exported_at" to JsonPrimitive(clock()),
                    "items" to JsonArray(items),
                ),
            )
        return withContext(Dispatchers.Default) { ExportFile.write(doc.toString().toByteArray(), password, ladder) }
    }

    /** One `otpauth://` URI per line (Ente/Aegis compatible). Unencrypted: the UI warns first. */
    suspend fun exportPlain(): String =
        vault.snapshot(includeTrashed = false).joinToString("\n", postfix = "\n") { OtpAuthUri.format(it.otp) }

    suspend fun import(
        bytes: ByteArray,
        password: String?,
    ): ImportOutcome =
        when (detect(bytes)) {
            ImportKind.UOTP_EXPORT -> {
                if (password == null) {
                    ImportOutcome.PasswordRequired(ImportKind.UOTP_EXPORT)
                } else {
                    decrypting { readOwnExport(withContext(Dispatchers.Default) { ExportFile.read(bytes, password) }) }
                }
            }

            ImportKind.ENTE_ENCRYPTED -> {
                if (password == null) {
                    ImportOutcome.PasswordRequired(ImportKind.ENTE_ENCRYPTED)
                } else {
                    decrypting { plain(withContext(Dispatchers.Default) { EnteExport.decrypt(String(bytes, Charsets.UTF_8), password) }) }
                }
            }

            ImportKind.FOREIGN -> {
                foreign(withContext(Dispatchers.Default) { ForeignImport.parse(bytes, password) })
            }

            ImportKind.PLAIN_LIST -> {
                plain(String(bytes, Charsets.UTF_8))
            }
        }

    private suspend fun foreign(parsed: ImportParse): ImportOutcome =
        when (parsed) {
            is ImportParse.PasswordRequired -> {
                ImportOutcome.PasswordRequired(ImportKind.FOREIGN, parsed.format)
            }

            is ImportParse.WrongPassword -> {
                ImportOutcome.WrongPassword
            }

            is ImportParse.Unsupported -> {
                ImportOutcome.Unreadable(parsed.format, parsed.reason)
            }

            is ImportParse.Parsed -> {
                if (parsed.accounts.isEmpty() && parsed.rejected > 0) {
                    ImportOutcome.Unreadable(
                        parsed.format,
                        "None of the ${parsed.rejected} entries could be imported (unsupported account types or damaged data)",
                    )
                } else {
                    ImportOutcome.Imported(vault.importAccounts(parsed.accounts).copy(rejected = parsed.rejected))
                }
            }
        }

    private suspend fun decrypting(block: suspend () -> ImportOutcome): ImportOutcome =
        try {
            block()
        } catch (_: CryptoException.AuthenticationFailed) {
            ImportOutcome.WrongPassword
        } catch (_: CryptoException.InvalidFormat) {
            ImportOutcome.Unsupported
        }

    private suspend fun plain(text: String): ImportOutcome {
        val parsed = PlainListImport.parse(text)
        if (parsed.accounts.isEmpty() && parsed.rejected > 0) return ImportOutcome.Unsupported
        return ImportOutcome.Imported(vault.import(parsed.accounts).copy(rejected = parsed.rejected))
    }

    private suspend fun readOwnExport(plain: ByteArray): ImportOutcome {
        val items =
            runCatching {
                Json
                    .parseToJsonElement(String(plain, Charsets.UTF_8))
                    .jsonObject
                    .getValue("items")
                    .jsonArray
            }.getOrNull() ?: return ImportOutcome.Unsupported
        val accounts = mutableListOf<ImportedAccount>()
        var rejected = 0
        for (element in items) {
            try {
                val item = ItemCodec.decode(UUID.randomUUID(), element.toString().toByteArray())
                // What was in the trash when the file was written stays out.
                if (!item.trashed) accounts += ImportedAccount(item.otp, item.notes, item.favorite)
            } catch (_: ItemFormatException) {
                rejected++
            }
        }
        return ImportOutcome.Imported(vault.importAccounts(accounts).copy(rejected = rejected))
    }
}
