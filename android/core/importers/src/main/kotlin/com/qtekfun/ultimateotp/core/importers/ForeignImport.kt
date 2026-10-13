// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * Reads the export files of other authenticator apps. [detect] is cheap (no key derivation) and
 * decides from the file's structure; [parse] does the work and never throws for bad input: every
 * failure is an [ImportParse] with a fixed message. Nothing is logged and no message includes
 * file content or secrets.
 *
 * Blocking and CPU heavy for encrypted files (scrypt, Argon2id, PBKDF2): call it off the main thread.
 */
object ForeignImport {
    /** What [bytes] is, without asking for a password. Null if it is none of the supported formats. */
    fun detect(bytes: ByteArray): ForeignFormat? =
        try {
            sniff(bytes)?.format
        } catch (_: ImportFailure) {
            null
        }

    /** Reads [bytes] with [password] (null for plain files, or to learn that one is needed). */
    fun parse(
        bytes: ByteArray,
        password: String? = null,
    ): ImportParse =
        try {
            if (bytes.size > MAX_IMPORT_BYTES) unsupported("The file is too large to be an authenticator export")
            val sniffed = sniff(bytes) ?: unsupported("Not a recognised export file")
            sniffed.read(password)
        } catch (e: ImportFailure) {
            ImportParse.Unsupported(null, e.reason)
        } catch (_: CryptoException) {
            ImportParse.Unsupported(null, "The file is damaged or uses unsupported encryption parameters")
        } catch (_: IllegalArgumentException) {
            ImportParse.Unsupported(null, "The file is damaged or not in a supported format")
        }

    private class Sniffed(
        val format: ForeignFormat,
        val read: (String?) -> ImportParse,
    )

    @Suppress("CyclomaticComplexMethod", "ReturnCount")
    private fun sniff(bytes: ByteArray): Sniffed? {
        if (bytes.isEmpty() || bytes.size > MAX_IMPORT_BYTES) return null
        if (RaivoReader.isZip(bytes)) {
            return Sniffed(ForeignFormat.RAIVO) { _ -> parseText(RaivoReader.unzip(bytes), null) }
        }
        val text = strictText(bytes)
        if (text == null) {
            // Not text: only andOTP's encrypted backups look like random bytes.
            return if (AndOtpReader.looksLikeEncrypted(bytes)) {
                Sniffed(ForeignFormat.ANDOTP) { pw -> AndOtpReader.parseEncrypted(bytes, pw) }
            } else {
                null
            }
        }
        return sniffText(text)
    }

    private fun parseText(
        text: String,
        password: String?,
    ): ImportParse = sniffText(text)?.read?.invoke(password) ?: unsupported("The zip does not contain a recognised export")

    private fun sniffText(text: String): Sniffed? {
        if (AndOtpReader.isPgpArmor(text)) {
            unsupported("OpenPGP-encrypted andOTP backups are not supported: decrypt the file with OpenKeychain or gpg first")
        }
        return when (val root = parseJson(text.trim())) {
            is JsonObject -> sniffObject(root)
            is JsonArray -> sniffArray(root)
            else -> if (BitwardenReader.looksLikeCsv(text)) Sniffed(ForeignFormat.BITWARDEN) { BitwardenReader.parseCsv(text) } else null
        }
    }

    private fun sniffObject(root: JsonObject): Sniffed? =
        when {
            AegisReader.looksLike(root) -> Sniffed(ForeignFormat.AEGIS) { AegisReader.parse(root, it) }
            TwoFasReader.looksLike(root) -> Sniffed(ForeignFormat.TWO_FAS) { TwoFasReader.parse(root, it) }
            BitwardenReader.looksLikeJson(root) -> Sniffed(ForeignFormat.BITWARDEN) { BitwardenReader.parseJson(root) }
            ProtonReader.looksLike(root) -> Sniffed(ForeignFormat.PROTON) { ProtonReader.parse(root, it) }
            else -> null
        }

    private fun sniffArray(array: JsonArray): Sniffed? =
        when {
            RaivoReader.looksLike(array) -> Sniffed(ForeignFormat.RAIVO) { RaivoReader.parse(array) }
            AndOtpReader.looksLikePlain(array) -> Sniffed(ForeignFormat.ANDOTP) { AndOtpReader.parsePlain(array) }
            else -> null
        }
}
