// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

/** Failures of this module. Messages never contain key material or plaintext. */
sealed class CryptoException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /** Wrong key or password, or tampered data (an AEAD tag or a signature did not verify). */
    class AuthenticationFailed(
        message: String = "authentication failed",
        cause: Throwable? = null,
    ) : CryptoException(message, cause)

    /** Malformed input: unknown version, wrong length, out-of-range parameters. */
    class InvalidFormat(
        message: String,
        cause: Throwable? = null,
    ) : CryptoException(message, cause)

    /** Argon2id could not allocate the requested memory at any rung of the ladder. */
    class KdfFailed(
        message: String,
    ) : CryptoException(message)
}

/** Throws [CryptoException.InvalidFormat]; keeps format readers' guard clauses short. */
internal fun invalidFormat(message: String): Nothing = throw CryptoException.InvalidFormat(message)
