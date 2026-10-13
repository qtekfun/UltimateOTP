// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.crypto.Pbkdf2
import com.qtekfun.ultimateotp.core.crypto.wipe
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * 2FAS backup (docs/import-formats.md §2): JSON with `services`, or, with a password,
 * `servicesEncrypted` = `base64(ciphertext+tag):base64(salt):base64(iv)`, key = PBKDF2-HMAC-SHA256
 * (10 000 iterations) and AES-256-GCM.
 */
internal object TwoFasReader {
    private const val MAX_SCHEMA = 4
    private const val ITERATIONS = 10_000
    private const val KEY_BYTES = 32
    private const val MIN_PARTS = 3

    fun looksLike(root: JsonObject): Boolean =
        root.containsKey("schemaVersion") && (root.containsKey("services") || root.containsKey("servicesEncrypted"))

    fun parse(
        root: JsonObject,
        password: String?,
    ): ImportParse {
        val schema = root.long("schemaVersion") ?: unsupported("2FAS backup without a schema version")
        if (schema > MAX_SCHEMA) unsupported("2FAS backup schema version $schema is newer than this app understands")
        val groups =
            root["groups"]
                .arr()
                .orEmpty()
                .mapNotNull { it.obj() }
                .mapNotNull { g ->
                    (g.str("id") ?: return@mapNotNull null) to g.str("name").orEmpty()
                }.toMap()
        val encrypted = root.str("servicesEncrypted")?.takeIf { it.isNotBlank() }
        val services: JsonArray =
            if (encrypted == null) {
                root["services"].arr() ?: unsupported("2FAS backup: no services list")
            } else {
                if (password == null) return ImportParse.PasswordRequired(ForeignFormat.TWO_FAS)
                try {
                    decrypt(encrypted, password)
                } catch (_: CryptoException.AuthenticationFailed) {
                    return ImportParse.WrongPassword(ForeignFormat.TWO_FAS)
                } catch (_: CryptoException.InvalidFormat) {
                    return ImportParse.Unsupported(ForeignFormat.TWO_FAS, "2FAS backup: damaged encrypted data")
                }
            }
        val (accounts, rejected) = collectEntries(services) { s -> account(s.obj() ?: return@collectEntries null, groups) }
        return ImportParse.Parsed(ForeignFormat.TWO_FAS, accounts, rejected)
    }

    private fun decrypt(
        encrypted: String,
        password: String,
    ): JsonArray {
        val parts = encrypted.split(':')
        if (parts.size < MIN_PARTS) throw CryptoException.InvalidFormat("2FAS parts")
        val data = base64(parts[0])
        val salt = base64(parts[1])
        val iv = base64(parts[2])
        var failure: CryptoException? = null
        for (candidate in passwordCandidates(password)) {
            val key = Pbkdf2.derive(Pbkdf2.HMAC_SHA256, candidate, salt, ITERATIONS, KEY_BYTES)
            try {
                val plain = aesGcmOpen(key, iv, data)
                val parsed = parseJson(String(plain, Charsets.UTF_8))
                plain.wipe()
                return parsed.arr() ?: throw CryptoException.InvalidFormat("services is not a list")
            } catch (e: CryptoException.AuthenticationFailed) {
                failure = e
            } finally {
                key.wipe()
            }
        }
        throw failure ?: CryptoException.AuthenticationFailed()
    }

    private fun account(
        service: JsonObject,
        groups: Map<String, String>,
    ): ImportedAccount? {
        val otpInfo = service["otp"].obj() ?: JsonObject(emptyMap())
        val type =
            when (otpInfo.str("tokenType")?.uppercase()) {
                null, "TOTP" -> OtpType.TOTP
                "HOTP" -> OtpType.HOTP
                "STEAM" -> OtpType.STEAM
                else -> return null
            }
        val algorithm =
            if (type ==
                OtpType.STEAM
            ) {
                OtpAlgorithm.SHA1
            } else {
                OtpAlgorithm.parse(otpInfo.str("algorithm") ?: "SHA1") ?: return null
            }
        val issuer = service.str("name")?.takeIf { it.isNotBlank() } ?: otpInfo.str("issuer").orEmpty()
        val label = otpInfo.str("account")?.takeIf { it.isNotBlank() } ?: otpInfo.str("label").orEmpty()
        val tag = service.str("groupId")?.let { groups[it] }?.takeIf { it.isNotBlank() }
        val otp =
            OtpParams(
                type = type,
                secret = secretOf(service.str("secret")),
                algorithm = algorithm,
                digits = if (type == OtpType.STEAM) OtpParams.STEAM_DIGITS else otpInfo.int("digits") ?: OtpParams.DEFAULT_DIGITS,
                period = otpInfo.int("period") ?: OtpParams.DEFAULT_PERIOD,
                counter = otpInfo.long("counter") ?: 0,
                issuer = issuer.trim(),
                label = label.trim(),
                tags = listOfNotNull(tag),
            )
        return ImportedAccount(otp)
    }

    private fun JsonArray?.orEmpty() = this ?: JsonArray(emptyList())
}
