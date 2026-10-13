// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

/**
 * Ente Auth adds a `codeDisplay` query parameter with JSON
 * (`{"pinned":false,"trashed":false,"tags":["Work"],…}`) to its `otpauth://` URIs. Only the tags
 * are imported; the rest is display state of Ente's own UI.
 */
internal object EnteCodeDisplay {
    private val TAGS = Regex("\"tags\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL)
    private val STRING = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"")

    fun tags(json: String?): List<String> {
        val array = json?.let { TAGS.find(it)?.groupValues?.get(1) } ?: return emptyList()
        return STRING
            .findAll(array)
            .map { unescape(it.groupValues[1]) }
            .filter { it.isNotBlank() }
            .toList()
    }

    private fun unescape(s: String): String = s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\/", "/")
}
