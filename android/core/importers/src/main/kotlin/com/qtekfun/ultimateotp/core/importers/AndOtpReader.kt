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
import kotlinx.serialization.json.JsonPrimitive
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * andOTP backup (docs/import-formats.md §3): a JSON array, or the password-encrypted binary of
 * andOTP 0.6.3+ (`iterations u32be || salt[12] || nonce[12] || AES-GCM ciphertext+tag`, key =
 * PBKDF2-HMAC-SHA1) or of older releases (`nonce[12] || ciphertext+tag`, key = SHA-256(password)).
 */
internal object AndOtpReader {
    private const val INT_BYTES = 4
    private const val SALT_BYTES = 12
    private const val NONCE_BYTES = 12
    private const val TAG_BYTES = 16
    private const val KEY_BYTES = 32
    private const val MAX_ITERATIONS = 10_000_000
    private const val PGP_ARMOR = "-----BEGIN PGP MESSAGE-----"

    fun looksLikePlain(array: JsonArray): Boolean =
        array.isNotEmpty() &&
            array.all { e ->
                val o = e.obj()
                o != null && o.containsKey("secret") && o.containsKey("type") && o.containsKey("algorithm") && !o.containsKey("kind")
            }

    fun looksLikeEncrypted(bytes: ByteArray): Boolean = bytes.size >= NONCE_BYTES + TAG_BYTES

    fun isPgpArmor(text: String): Boolean = text.trimStart().startsWith(PGP_ARMOR)

    fun parsePlain(array: JsonArray): ImportParse {
        val (accounts, rejected) = collectEntries(array) { e -> account(e.obj() ?: return@collectEntries null) }
        return ImportParse.Parsed(ForeignFormat.ANDOTP, accounts, rejected)
    }

    fun parseEncrypted(
        bytes: ByteArray,
        password: String?,
    ): ImportParse {
        if (!looksLikeEncrypted(bytes)) unsupported("Not an andOTP backup (too short)")
        if (password == null) return ImportParse.PasswordRequired(ForeignFormat.ANDOTP)
        for (candidate in passwordCandidates(password)) {
            decryptOld(bytes, candidate)?.let { return readDecrypted(it) }
            decryptNew(bytes, candidate)?.let { return readDecrypted(it) }
        }
        return ImportParse.WrongPassword(ForeignFormat.ANDOTP)
    }

    private fun readDecrypted(plain: ByteArray): ImportParse {
        val text = strictText(plain)
        plain.wipe()
        val array = text?.let(::parseJson).arr()
        return if (array == null) {
            ImportParse.Unsupported(ForeignFormat.ANDOTP, "andOTP backup: decrypted content is not a list of accounts")
        } else {
            parsePlain(array)
        }
    }

    /** Pre-0.6.3 files: the key is the bare SHA-256 of the password. Cheap, so tried first. */
    private fun decryptOld(
        data: ByteArray,
        password: ByteArray,
    ): ByteArray? {
        val key = MessageDigest.getInstance("SHA-256").digest(password)
        return try {
            aesGcmOpen(key, data.copyOfRange(0, NONCE_BYTES), data.copyOfRange(NONCE_BYTES, data.size))
        } catch (_: CryptoException) {
            null
        } finally {
            key.wipe()
        }
    }

    private fun decryptNew(
        data: ByteArray,
        password: ByteArray,
    ): ByteArray? {
        if (data.size < INT_BYTES + SALT_BYTES + NONCE_BYTES + TAG_BYTES) return null
        val iterations = ByteBuffer.wrap(data, 0, INT_BYTES).int
        // A garbage count means this is not the new format; a huge one would stall the device.
        if (iterations !in 1..MAX_ITERATIONS) return null
        val salt = data.copyOfRange(INT_BYTES, INT_BYTES + SALT_BYTES)
        val key = Pbkdf2.derive(Pbkdf2.HMAC_SHA1, password, salt, iterations, KEY_BYTES)
        return try {
            val nonceStart = INT_BYTES + SALT_BYTES
            aesGcmOpen(key, data.copyOfRange(nonceStart, nonceStart + NONCE_BYTES), data.copyOfRange(nonceStart + NONCE_BYTES, data.size))
        } catch (_: CryptoException) {
            null
        } finally {
            key.wipe()
        }
    }

    /** Older andOTP versions stored `Issuer:account` in the label next to the issuer field. */
    private fun withoutIssuerPrefix(
        label: String,
        issuer: String,
    ): String = if (issuer.isNotEmpty() && label.startsWith("$issuer:")) label.removePrefix("$issuer:").trim() else label

    private fun account(e: JsonObject): ImportedAccount? {
        val type =
            when (e.str("type")?.uppercase()) {
                "TOTP" -> OtpType.TOTP
                "HOTP" -> OtpType.HOTP
                "STEAM" -> OtpType.STEAM
                else -> return null // MOTP and unknown
            }
        val algorithm = if (type == OtpType.STEAM) OtpAlgorithm.SHA1 else OtpAlgorithm.parse(e.str("algorithm")) ?: return null
        val rawLabel = e.str("label").orEmpty()
        val (issuer, label) =
            if (e.containsKey("issuer")) {
                e.str("issuer").orEmpty() to rawLabel
            } else if (" - " in rawLabel) {
                rawLabel.substringBefore(" - ") to rawLabel.substringAfter(" - ")
            } else {
                "" to rawLabel
            }
        val tags =
            e["tags"]
                .arr()
                ?.mapNotNull { (it as? JsonPrimitive)?.content }
                ?.filter { it.isNotBlank() }
                .orEmpty()
        val otp =
            OtpParams(
                type = type,
                secret = secretOf(e.str("secret")),
                algorithm = algorithm,
                digits = if (type == OtpType.STEAM) OtpParams.STEAM_DIGITS else e.int("digits") ?: OtpParams.DEFAULT_DIGITS,
                period = e.int("period") ?: OtpParams.DEFAULT_PERIOD,
                counter = e.long("counter") ?: 0,
                issuer = issuer.trim(),
                label = withoutIssuerPrefix(label.trim(), issuer.trim()),
                tags = tags,
            )
        return ImportedAccount(otp)
    }
}
