// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.crypto.KdfParams
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.crypto.wipe
import kotlinx.serialization.json.JsonObject

/**
 * Proton Authenticator export (docs/import-formats.md §6): `{"version":1,"entries":[{"content":
 * {"uri","entry_type","name"},"note"}]}`, or `{"version":1,"salt","content"}` encrypted with
 * Argon2id (19 MiB, 2 passes, 1 lane) and AES-256-GCM with the AAD `proton.authenticator.export.v1`.
 */
internal object ProtonReader {
    private const val VERSION = 1L
    private const val MEMORY_BYTES = 19L * 1024 * 1024
    private const val OPS = 2L
    private const val NONCE_BYTES = 12
    private val AAD = "proton.authenticator.export.v1".toByteArray(Charsets.UTF_8)

    fun looksLike(root: JsonObject): Boolean =
        root["version"] != null &&
            (root["entries"].arr() != null || (root.containsKey("salt") && root.containsKey("content")))

    fun parse(
        root: JsonObject,
        password: String?,
    ): ImportParse {
        if (root.long("version") != VERSION) unsupported("Unsupported Proton Authenticator export version (only version 1 is known)")
        if (root.containsKey("salt") && root.containsKey("content")) {
            if (password == null) return ImportParse.PasswordRequired(ForeignFormat.PROTON)
            val decrypted =
                try {
                    decrypt(root, password)
                } catch (_: CryptoException.AuthenticationFailed) {
                    return ImportParse.WrongPassword(ForeignFormat.PROTON)
                } catch (_: CryptoException.InvalidFormat) {
                    return ImportParse.Unsupported(ForeignFormat.PROTON, "Proton Authenticator export: damaged encrypted data")
                }
            return plain(decrypted)
        }
        return plain(root)
    }

    private fun decrypt(
        root: JsonObject,
        password: String,
    ): JsonObject {
        val salt = base64(root.str("salt") ?: throw CryptoException.InvalidFormat("salt"))
        val content = base64(root.str("content") ?: throw CryptoException.InvalidFormat("content"))
        if (salt.size != KdfParams.SALT_BYTES || content.size <= NONCE_BYTES) throw CryptoException.InvalidFormat("sizes")
        var failure: CryptoException? = null
        for (candidate in passwordCandidates(password)) {
            val key = PasswordKdf.deriveRaw(candidate, KdfParams(OPS, MEMORY_BYTES, salt))
            try {
                val plain =
                    aesGcmOpen(key, content.copyOfRange(0, NONCE_BYTES), content.copyOfRange(NONCE_BYTES, content.size), AAD)
                val parsed = parseJson(String(plain, Charsets.UTF_8))
                plain.wipe()
                return parsed.obj() ?: throw CryptoException.InvalidFormat("not an object")
            } catch (e: CryptoException.AuthenticationFailed) {
                failure = e
            } finally {
                key.wipe()
            }
        }
        throw failure ?: CryptoException.AuthenticationFailed()
    }

    private fun plain(root: JsonObject): ImportParse {
        val entries = root["entries"].arr() ?: unsupported("Proton Authenticator export without entries")
        val (accounts, rejected) = collectEntries(entries) { e -> account(e.obj() ?: return@collectEntries null) }
        return ImportParse.Parsed(ForeignFormat.PROTON, accounts, rejected)
    }

    private fun account(entry: JsonObject): ImportedAccount? {
        val content = entry["content"].obj() ?: return null
        val uri = content.str("uri") ?: return null
        val parsed = parseUriOrSteam(uri)
        val name = content.str("name").orEmpty().trim()
        return ImportedAccount(parsed.copy(label = name.ifEmpty { parsed.label }), notes = entry.str("note").orEmpty())
    }
}
