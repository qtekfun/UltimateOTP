// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

/** Outcome of importing many accounts: what parsed, and how many lines were rejected (no content). */
data class ImportResult(
    val accounts: List<OtpParams>,
    val rejected: Int,
)

/**
 * A text file with one URI per line: Ente Auth's plain export, Aegis's and 2FAS's "otpauth list",
 * or a hand-made list. Also accepts `otpauth-migration://` lines (Google Authenticator).
 */
object PlainListImport {
    fun parse(text: String): ImportResult {
        val accounts = mutableListOf<OtpParams>()
        var rejected = 0
        for (raw in text.lineSequence()) {
            val line = unquote(raw.trim().removePrefix(""))
            if (line.isEmpty()) continue
            when {
                line.startsWith("otpauth://", ignoreCase = true) -> {
                    try {
                        accounts += OtpAuthUri.parse(line)
                    } catch (_: OtpUriException) {
                        rejected++
                    }
                }

                line.startsWith(GoogleMigration.SCHEME, ignoreCase = true) -> {
                    try {
                        accounts += GoogleMigration.parse(line)
                    } catch (_: OtpUriException) {
                        rejected++
                    }
                }

                else -> {
                    rejected++
                }
            }
        }
        return ImportResult(accounts, rejected)
    }

    /** Ente's `toOTPAuthUrlFormat` JSON-quotes the URI; take it out of the quotes. */
    private fun unquote(line: String): String =
        if (line.length >= 2 && line.startsWith('"') && line.endsWith('"')) {
            line.substring(1, line.length - 1).replace("\\/", "/").replace("\\\"", "\"")
        } else {
            line
        }
}
