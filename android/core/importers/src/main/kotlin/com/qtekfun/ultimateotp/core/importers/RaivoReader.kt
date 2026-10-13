// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipInputStream

/**
 * Raivo OTP export (docs/import-formats.md §4): a JSON array of string-valued objects
 * (`kind`, `issuer`, `account`, `secret`, `algorithm`, `digits`, `timer`, `counter`), as the bare
 * `.json` or inside the unencrypted `.zip` Raivo writes. Password-protected zips are not read.
 */
internal object RaivoReader {
    private const val ZIP_MAGIC_0 = 'P'.code.toByte()
    private const val ZIP_MAGIC_1 = 'K'.code.toByte()
    private const val ZIP_LOCAL_HEADER_BYTES = 30
    private const val FLAG_OFFSET = 6
    private const val FLAG_ENCRYPTED = 0x01
    private const val MAX_ENTRY_BYTES = 8 * 1024 * 1024

    fun isZip(bytes: ByteArray): Boolean =
        bytes.size > 4 && bytes[0] == ZIP_MAGIC_0 && bytes[1] == ZIP_MAGIC_1 && bytes[2] == 3.toByte() && bytes[3] == 4.toByte()

    fun looksLike(array: JsonArray): Boolean =
        array.isNotEmpty() &&
            array.all { e ->
                val o = e.obj()
                o != null && o.containsKey("kind") && o.containsKey("secret")
            }

    /** The JSON text inside a Raivo zip. */
    fun unzip(bytes: ByteArray): String {
        if (bytes.size >= ZIP_LOCAL_HEADER_BYTES && bytes[FLAG_OFFSET].toInt() and FLAG_ENCRYPTED != 0) {
            unsupported("This Raivo export is a password-protected zip: extract it first and import the .json file inside")
        }
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.isDirectory || !entry.name.endsWith(".json", ignoreCase = true)) continue
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(BUFFER)
                while (true) {
                    val n = zip.read(buffer)
                    if (n < 0) break
                    if (out.size() + n > MAX_ENTRY_BYTES) unsupported("The zip's content is too large to be a Raivo export")
                    out.write(buffer, 0, n)
                }
                return strictText(out.toByteArray()) ?: unsupported("The zip does not contain a readable Raivo export")
            }
        }
        unsupported("The zip does not contain a Raivo .json export")
    }

    private const val BUFFER = 8192

    fun parse(array: JsonArray): ImportParse {
        val (accounts, rejected) = collectEntries(array) { e -> account(e.obj() ?: return@collectEntries null) }
        return ImportParse.Parsed(ForeignFormat.RAIVO, accounts, rejected)
    }

    private fun account(e: JsonObject): ImportedAccount? {
        val type =
            when (e.str("kind")?.uppercase()) {
                "TOTP" -> OtpType.TOTP
                "HOTP" -> OtpType.HOTP
                "STEAM" -> OtpType.STEAM
                else -> return null
            }
        val algorithm = if (type == OtpType.STEAM) OtpAlgorithm.SHA1 else OtpAlgorithm.parse(e.str("algorithm") ?: "SHA1") ?: return null
        val otp =
            OtpParams(
                type = type,
                secret = secretOf(e.str("secret")),
                algorithm = algorithm,
                digits = if (type == OtpType.STEAM) OtpParams.STEAM_DIGITS else e.int("digits") ?: OtpParams.DEFAULT_DIGITS,
                period = e.int("timer") ?: OtpParams.DEFAULT_PERIOD,
                counter = e.long("counter") ?: 0,
                issuer = e.str("issuer").orEmpty().trim(),
                label = e.str("account").orEmpty().trim(),
            )
        return ImportedAccount(otp)
    }
}
