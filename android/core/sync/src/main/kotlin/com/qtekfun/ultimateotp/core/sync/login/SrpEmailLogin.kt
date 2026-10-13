// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.login

import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.api.SrpAttributes
import com.qtekfun.ultimateotp.core.sync.api.UotpApi

/**
 * [EmailLogin] on contract 1.1.0: `/srp/attributes`, `/login/email-code`, `/srp/session` (which
 * checks the emailed code), `/srp/verify`. The code works once, so a wrong password sends the
 * user back to request a new one.
 */
class SrpEmailLogin(
    private val engine: SyncEngine,
    private val apiFor: (String) -> UotpApi,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / MILLIS },
) : EmailLogin {
    private val attributes = mutableMapOf<String, SrpAttributes>()
    private val handshakes = mutableMapOf<String, SyncEngine.SrpHandshake>()

    override suspend fun requestCode(
        server: String,
        email: String,
    ): Pair<EmailLogin.Ticket, Long> {
        val api = apiFor(server)
        val attrs = api.srpAttributes(email)
        if (attrs.emailCodeRequired) api.requestEmailCode(email)
        attributes[key(server, email)] = attrs
        return EmailLogin.Ticket(server, email, attrs.emailCodeRequired) to nowSeconds() + RESEND_COOLDOWN_S
    }

    override suspend fun verifyCode(
        ticket: EmailLogin.Ticket,
        code: String,
    ): EmailLogin.Ticket {
        val attrs = attributes[key(ticket.server, ticket.email)] ?: error("request a code first")
        handshakes[key(ticket.server, ticket.email)] =
            engine.startSrp(ticket.server, ticket.email, attrs, code.takeIf { ticket.codeRequired })
        return ticket
    }

    override suspend fun complete(
        ticket: EmailLogin.Ticket,
        password: String,
        label: String,
    ) {
        val handshake = handshakes.remove(key(ticket.server, ticket.email)) ?: error("start the session first")
        engine.completeSrp(ticket.server, handshake, password, label)
        attributes.remove(key(ticket.server, ticket.email))
    }

    private fun key(
        server: String,
        email: String,
    ) = "$server|$email"

    private companion object {
        const val RESEND_COOLDOWN_S = 60L
        const val MILLIS = 1000L
    }
}
