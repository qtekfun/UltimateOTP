// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.otp.Base32
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import kotlinx.serialization.json.JsonObject

/**
 * Bitwarden vault export (docs/import-formats.md §5): the unencrypted `.json` (`items[].login.totp`)
 * or `.csv` (`login_totp` column). The TOTP value is an `otpauth://` URI, Steam's `steam://SECRET`,
 * or a bare base32 secret. Only login items with a TOTP value are read.
 */
internal object BitwardenReader {
    private const val CSV_TOTP = "login_totp"

    fun looksLikeJson(root: JsonObject): Boolean =
        root["items"].arr() != null && (root.containsKey("folders") || root.containsKey("encrypted"))

    fun looksLikeCsv(text: String): Boolean {
        val header = text.lineSequence().firstOrNull { it.isNotBlank() } ?: return false
        return CSV_TOTP in header.split(',').map { it.trim().trim('"') }
    }

    fun parseJson(root: JsonObject): ImportParse {
        if (root.bool("encrypted")) {
            unsupported("This Bitwarden export is encrypted: export it again as an unencrypted .json or .csv file")
        }
        val items = root["items"].arr() ?: unsupported("Bitwarden export without items")
        val rows =
            items.mapNotNull { it.obj() }.mapNotNull { item ->
                val login = item["login"].obj() ?: return@mapNotNull null
                val totp = login.str("totp")?.trim().orEmpty()
                if (totp.isEmpty()) {
                    null
                } else {
                    Row(
                        totp,
                        item.str("name").orEmpty(),
                        login.str("username").orEmpty(),
                        item.str("notes").orEmpty(),
                        item.bool("favorite"),
                    )
                }
            }
        return build(rows)
    }

    fun parseCsv(text: String): ImportParse {
        val table = Csv.parse(text)
        val header = table.firstOrNull()?.map { it.trim() } ?: unsupported("Empty Bitwarden CSV")
        val totp = header.indexOf(CSV_TOTP)
        if (totp < 0) unsupported("Bitwarden CSV without a login_totp column")
        val name = header.indexOf("name")
        val user = header.indexOf("login_username")
        val notes = header.indexOf("notes")
        val fav = header.indexOf("favorite")

        fun List<String>.at(i: Int) = if (i in indices) this[i].trim() else ""
        val rows =
            table.drop(1).mapNotNull { r ->
                val value = r.at(totp)
                if (value.isEmpty()) {
                    null
                } else {
                    Row(value, r.at(name), r.at(user), r.at(notes), r.at(fav).let { it == "1" || it.equals("true", ignoreCase = true) })
                }
            }
        return build(rows)
    }

    private class Row(
        val totp: String,
        val name: String,
        val username: String,
        val notes: String,
        val favorite: Boolean,
    )

    private fun build(rows: List<Row>): ImportParse {
        val (accounts, rejected) = collectEntries(rows) { row -> account(row) }
        return ImportParse.Parsed(ForeignFormat.BITWARDEN, accounts, rejected)
    }

    private fun account(row: Row): ImportedAccount {
        val value = row.totp
        val parsed =
            if (value.contains("://")) {
                parseUriOrSteam(value)
            } else {
                // A bare secret, as Bitwarden's own field accepts.
                OtpParams(OtpType.TOTP, Base32.decode(value))
            }
        val issuer = parsed.issuer.ifBlank { row.name }
        val label = parsed.label.ifBlank { row.username }
        return ImportedAccount(parsed.copy(issuer = issuer.trim(), label = label.trim()), notes = row.notes, favorite = row.favorite)
    }
}

/** RFC 4180 CSV: quoted fields, doubled quotes, line breaks inside quotes. */
internal object Csv {
    fun parse(text: String): List<List<String>> {
        val rows = mutableListOf<List<String>>()
        var row = mutableListOf<String>()
        val field = StringBuilder()
        var quoted = false
        var i = 0
        val s = text.removePrefix("")
        while (i < s.length) {
            val c = s[i]
            when {
                quoted && c == '"' && i + 1 < s.length && s[i + 1] == '"' -> {
                    field.append('"')
                    i++
                }

                c == '"' -> {
                    quoted = !quoted
                }

                !quoted && c == ',' -> {
                    row.add(field.toString())
                    field.setLength(0)
                }

                !quoted && (c == '\n' || c == '\r') -> {
                    if (c == '\r' && i + 1 < s.length && s[i + 1] == '\n') i++
                    row.add(field.toString())
                    field.setLength(0)
                    if (row.any { it.isNotEmpty() }) rows.add(row)
                    row = mutableListOf()
                }

                else -> {
                    field.append(c)
                }
            }
            i++
        }
        if (field.isNotEmpty() || row.isNotEmpty()) {
            row.add(field.toString())
            if (row.any { it.isNotEmpty() }) rows.add(row)
        }
        return rows
    }
}
