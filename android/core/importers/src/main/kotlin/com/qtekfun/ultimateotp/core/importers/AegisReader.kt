// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.crypto.Scrypt
import com.qtekfun.ultimateotp.core.crypto.wipe
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Aegis vault (docs/import-formats.md §1; Aegis `docs/vault.md`): plain JSON, or encrypted with a
 * password slot (scrypt, then AES-256-GCM wrapping a master key that encrypts the `db`).
 */
internal object AegisReader {
    private const val SLOT_PASSWORD = 1L
    private const val MAX_DB_VERSION = 3
    private const val KEY_BYTES = 32
    private const val TAG_BYTES = 16

    fun looksLike(root: JsonObject): Boolean = root["header"] is JsonObject && root.containsKey("db") && root["version"] != null

    fun parse(
        root: JsonObject,
        password: String?,
    ): ImportParse {
        if (root.long("version") != 1L) unsupported("Unsupported Aegis vault version (only version 1 is known)")
        val header = root["header"].obj() ?: unsupported("Aegis vault without a header")
        val db = root["db"]
        val slots = header["slots"].arr()
        if (slots == null && db is JsonObject) return plain(db)
        if (db !is JsonPrimitive || !db.isString) unsupported("Aegis vault: unreadable content")
        if (slots == null) unsupported("Aegis vault: encrypted content without key slots")
        if (password == null) return ImportParse.PasswordRequired(ForeignFormat.AEGIS)
        return try {
            plain(decrypt(header, slots, db.content, password))
        } catch (_: CryptoException.AuthenticationFailed) {
            ImportParse.WrongPassword(ForeignFormat.AEGIS)
        } catch (_: CryptoException.InvalidFormat) {
            ImportParse.Unsupported(ForeignFormat.AEGIS, "Aegis vault: damaged or unsupported encryption parameters")
        }
    }

    private fun decrypt(
        header: JsonObject,
        slots: kotlinx.serialization.json.JsonArray,
        db: String,
        password: String,
    ): JsonObject {
        val passwordSlots = slots.mapNotNull { it.obj() }.filter { it.long("type") == SLOT_PASSWORD }
        if (passwordSlots.isEmpty()) unsupported("This Aegis vault has no password slot (only biometric or raw key slots)")
        val master = unwrapMasterKey(passwordSlots, password)
        try {
            val params = header["params"].obj() ?: throw CryptoException.InvalidFormat("no params")
            val nonce = hex(params.str("nonce") ?: throw CryptoException.InvalidFormat("no nonce"))
            val tag = hex(params.str("tag") ?: throw CryptoException.InvalidFormat("no tag"))
            val plain = aesGcmOpen(master, nonce, base64(db) + tag)
            val parsed = parseJson(String(plain, Charsets.UTF_8))
            plain.wipe()
            return parsed.obj() ?: throw CryptoException.InvalidFormat("db is not an object")
        } finally {
            master.wipe()
        }
    }

    private fun unwrapMasterKey(
        slots: List<JsonObject>,
        password: String,
    ): ByteArray {
        var failure: CryptoException? = null
        for (slot in slots) {
            try {
                val n = slot.int("n") ?: throw CryptoException.InvalidFormat("no n")
                val r = slot.int("r") ?: throw CryptoException.InvalidFormat("no r")
                val p = slot.int("p") ?: throw CryptoException.InvalidFormat("no p")
                val salt = hex(slot.str("salt") ?: throw CryptoException.InvalidFormat("no salt"))
                val keyParams = slot["key_params"].obj() ?: throw CryptoException.InvalidFormat("no key_params")
                val nonce = hex(keyParams.str("nonce") ?: throw CryptoException.InvalidFormat("no nonce"))
                val tag = hex(keyParams.str("tag") ?: throw CryptoException.InvalidFormat("no tag"))
                val wrapped = hex(slot.str("key") ?: throw CryptoException.InvalidFormat("no key"))
                if (wrapped.size != KEY_BYTES || tag.size != TAG_BYTES) throw CryptoException.InvalidFormat("bad key sizes")
                for (candidate in passwordCandidates(password)) {
                    val kek = Scrypt.derive(candidate, salt, n, r, p, KEY_BYTES)
                    try {
                        return aesGcmOpen(kek, nonce, wrapped + tag)
                    } catch (e: CryptoException.AuthenticationFailed) {
                        failure = e
                    } finally {
                        kek.wipe()
                    }
                }
            } catch (e: CryptoException.InvalidFormat) {
                failure = failure ?: e
            }
        }
        throw failure ?: CryptoException.AuthenticationFailed()
    }

    private fun plain(db: JsonObject): ImportParse {
        val version = db.long("version") ?: unsupported("Aegis vault: missing content version")
        if (version > MAX_DB_VERSION) unsupported("Aegis vault content version $version is newer than this app understands")
        val entries = db["entries"].arr() ?: unsupported("Aegis vault: no entries list")
        val groups =
            db["groups"]
                .arr()
                .orEmpty()
                .mapNotNull { it.obj() }
                .mapNotNull { g ->
                    val id = g.str("uuid") ?: return@mapNotNull null
                    id to g.str("name").orEmpty()
                }.toMap()
        val (accounts, rejected) = collectEntries(entries) { entry -> account(entry.obj() ?: return@collectEntries null, groups) }
        return ImportParse.Parsed(ForeignFormat.AEGIS, accounts, rejected)
    }

    private fun account(
        entry: JsonObject,
        groups: Map<String, String>,
    ): ImportedAccount? {
        val type =
            when (entry.str("type")?.lowercase()) {
                "totp" -> OtpType.TOTP
                "hotp" -> OtpType.HOTP
                "steam" -> OtpType.STEAM
                else -> return null // motp, yandex, unknown
            }
        val info = entry["info"].obj() ?: return null
        val algorithm = if (type == OtpType.STEAM) OtpAlgorithm.SHA1 else OtpAlgorithm.parse(info.str("algo")) ?: return null
        val tags =
            entry["groups"]
                .arr()
                .orEmpty()
                .mapNotNull { (it as? JsonPrimitive)?.content }
                .mapNotNull { groups[it] }
                .filter { it.isNotBlank() }
        val otp =
            OtpParams(
                type = type,
                secret = secretOf(info.str("secret")),
                algorithm = algorithm,
                digits = if (type == OtpType.STEAM) OtpParams.STEAM_DIGITS else info.int("digits") ?: OtpParams.DEFAULT_DIGITS,
                period = info.int("period") ?: OtpParams.DEFAULT_PERIOD,
                counter = info.long("counter") ?: 0,
                issuer = entry.str("issuer").orEmpty().trim(),
                label = entry.str("name").orEmpty().trim(),
                tags = tags,
            )
        return ImportedAccount(otp, notes = entry.str("note").orEmpty(), favorite = entry.bool("favorite"))
    }

    private fun kotlinx.serialization.json.JsonArray?.orEmpty() = this ?: kotlinx.serialization.json.JsonArray(emptyList())
}
