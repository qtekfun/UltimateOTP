// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.otp.OtpParams

/** The export formats of other apps this module reads. */
enum class ForeignFormat(
    val displayName: String,
) {
    AEGIS("Aegis"),
    TWO_FAS("2FAS"),
    ANDOTP("andOTP"),
    RAIVO("Raivo OTP"),
    BITWARDEN("Bitwarden"),
    PROTON("Proton Authenticator"),
}

/** An account read from a foreign file: the OTP parameters plus what the vault item also keeps. */
class ImportedAccount(
    val otp: OtpParams,
    val notes: String = "",
    val favorite: Boolean = false,
) {
    /** No secret, issuer or label: safe for logs. */
    override fun toString(): String = "ImportedAccount(type=${otp.type})"
}

/** The outcome of reading one file. Messages are fixed texts: they never include file content. */
sealed interface ImportParse {
    data class Parsed(
        val format: ForeignFormat,
        val accounts: List<ImportedAccount>,
        /** Entries that were present but unusable (unknown type, bad secret, unsupported algorithm). */
        val rejected: Int,
    ) : ImportParse

    /** The file is encrypted and no password was given. */
    data class PasswordRequired(
        val format: ForeignFormat,
    ) : ImportParse

    /** Wrong password, or a damaged file (the two cannot be told apart by an AEAD). */
    data class WrongPassword(
        val format: ForeignFormat,
    ) : ImportParse

    /** A recognised or damaged file this module cannot read; [reason] explains why in one line. */
    data class Unsupported(
        val format: ForeignFormat?,
        val reason: String,
    ) : ImportParse
}

/** Internal control flow: a whole-file failure with a user-facing, content-free reason. */
internal class ImportFailure(
    val reason: String,
) : Exception(reason)

internal fun unsupported(reason: String): Nothing = throw ImportFailure(reason)
