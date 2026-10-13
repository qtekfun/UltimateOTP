// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import java.net.URLDecoder
import java.net.URLEncoder

/** `uotp://pair?v=1&s=<server>&p=<pairing id>&k=<secret>&a=<approver Ed25519>` (crypto-format.md §5.4). */
data class PairLink(
    val server: String,
    val pairingId: String,
    val secret: String,
    val approverEd25519: String,
) {
    fun format(): String = "uotp://pair?v=1&s=${enc(server)}&p=${enc(pairingId)}&k=${enc(secret)}&a=${enc(approverEd25519)}"

    /** No secret in logs. */
    override fun toString(): String = "PairLink(server=$server, pairingId=$pairingId)"

    companion object {
        private const val PART_A = 3

        fun parse(link: String): PairLink? {
            val q = query(link, "uotp://pair")?.takeIf { it["v"] == "1" }
            val parts = listOf("s", "p", "k", "a").map { q?.get(it) }
            return if (parts.any { it == null }) null else parts.requireNoNulls().let { PairLink(it[0], it[1], it[2], it[PART_A]) }
        }
    }
}

/** The server CLI's `uotp://enroll?server=…&token=…` link (an enrollment token for this device). */
data class EnrollLink(
    val server: String,
    val token: String,
) {
    override fun toString(): String = "EnrollLink(server=$server)"

    companion object {
        fun parse(link: String): EnrollLink? {
            val q = query(link, "uotp://enroll")
            val server = q?.get("server")
            val token = q?.get("token")
            return if (server == null || token == null) null else EnrollLink(server, token)
        }
    }
}

private fun enc(s: String): String = URLEncoder.encode(s, Charsets.UTF_8.name())

internal fun query(
    link: String,
    prefix: String,
): Map<String, String>? {
    val trimmed = link.trim()
    if (!trimmed.startsWith(prefix, ignoreCase = true)) return null
    val q = trimmed.substringAfter('?', "")
    return q.split('&').filter { '=' in it }.associate {
        URLDecoder.decode(it.substringBefore('='), Charsets.UTF_8.name()) to
            URLDecoder.decode(it.substringAfter('='), Charsets.UTF_8.name())
    }
}

/**
 * Where enrollment and recovery requests go (decisions.md item 4). The server keeps those routes
 * LAN-only by default; the client mirrors it so a password never travels to an address the owner
 * did not mean, unless the owner allowed remote enrollment.
 */
object EnrollmentPolicy {
    sealed interface Choice {
        data class Use(
            val url: String,
        ) : Choice

        /** Remote enrollment is off and no LAN address is configured. */
        data object Refused : Choice
    }

    fun choose(
        serverUrl: String,
        enrollmentUrl: String,
        allowRemote: Boolean,
    ): Choice =
        when {
            enrollmentUrl.isNotBlank() -> Choice.Use(enrollmentUrl)
            isLocal(serverUrl) || allowRemote -> Choice.Use(serverUrl)
            else -> Choice.Refused
        }

    /** RFC 1918, loopback, link-local, ULA, CGNAT (Tailscale) and `.local`/`.lan`/`.home.arpa` names. */
    fun isLocal(url: String): Boolean {
        val host =
            url
                .substringAfter("://")
                .substringBefore('/')
                .substringBefore('@')
                .let {
                    if (it.startsWith("[")) it.substringAfter('[').substringBefore(']') else it.substringBefore(':')
                }.lowercase()
        return host == "localhost" || host.endsWith(".local") || host.endsWith(".lan") || host.endsWith(".home.arpa") ||
            PRIVATE_V4.any { it.matches(host) } || host.startsWith("fd") || host.startsWith("fe80:") || host == "::1"
    }

    private val PRIVATE_V4 =
        listOf(
            Regex("""^10\.\d+\.\d+\.\d+$"""),
            Regex("""^192\.168\.\d+\.\d+$"""),
            Regex("""^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"""),
            Regex("""^127\.\d+\.\d+\.\d+$"""),
            Regex("""^169\.254\.\d+\.\d+$"""),
            Regex("""^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+$"""),
        )
}
