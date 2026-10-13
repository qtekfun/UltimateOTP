// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.login

/**
 * New-device login like Ente Auth (decisions 6 and 13): email, a 6-digit code sent by email,
 * then the SRP-6a proof of the password (crypto-format.md §4.4), unwrapping the vault key and
 * registering this device's keys. The HTTP shapes come from contracts/openapi.yaml.
 */
interface EmailLogin {
    /** Progress of one login, returned by each step. Kept in memory only. */
    class Ticket(
        val server: String,
        val email: String,
        val codeRequired: Boolean = true,
    )

    /** Asks the server to email a code. @return when a new code may be requested (Unix seconds). */
    suspend fun requestCode(
        server: String,
        email: String,
    ): Pair<Ticket, Long>

    /** Checks the emailed code (10 minutes, at most 5 attempts on the server); "" when none is required. */
    suspend fun verifyCode(
        ticket: Ticket,
        code: String,
    ): Ticket

    /** SRP proof, server proof check, vault key unwrap and device registration. */
    suspend fun complete(
        ticket: Ticket,
        password: String,
        label: String,
    )
}

/** Until the server publishes the login routes in the contract: every step reports it. */
class EmailLoginUnavailable : EmailLogin {
    override suspend fun requestCode(
        server: String,
        email: String,
    ): Pair<EmailLogin.Ticket, Long> = unavailable()

    override suspend fun verifyCode(
        ticket: EmailLogin.Ticket,
        code: String,
    ): EmailLogin.Ticket = unavailable()

    override suspend fun complete(
        ticket: EmailLogin.Ticket,
        password: String,
        label: String,
    ): Unit = unavailable()

    private fun unavailable(): Nothing = throw UnsupportedOperationException("login routes not in the contract yet")
}
