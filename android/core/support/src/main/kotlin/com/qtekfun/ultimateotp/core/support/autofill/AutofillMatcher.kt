// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support.autofill

/** What matching needs to know of one entry: no secret, no code. */
class AutofillCandidate(
    val id: String,
    val issuer: String,
    /** The user-editable associations: Android package names and web domains. */
    val associations: List<String> = emptyList(),
) {
    override fun toString(): String = "AutofillCandidate(id=$id)"
}

enum class MatchKind {
    /** The user associated this entry with the app or domain. Always first. */
    EXPLICIT,

    /** The entry's issuer is (or names) the web domain being filled. */
    ISSUER_DOMAIN,

    /** The issuer equals a segment of the app's package name. Weakest. */
    ISSUER_PACKAGE,
}

class AutofillMatch(
    val candidate: AutofillCandidate,
    val kind: MatchKind,
)

/**
 * Decides which entries to offer for an app package and/or web domain (docs/autofill.md).
 * Explicit associations come first, then issuer-based guesses; nothing matches when neither the
 * package nor a domain is known, and the app never fills itself.
 */
object AutofillMatcher {
    private const val MIN_ISSUER = 3
    private const val THREE = 3
    private const val DEFAULT_LIMIT = 5
    private val GENERIC_SEGMENTS = setOf("com", "org", "net", "io", "app", "apps", "android", "mobile", "www", "co", "de", "uk")
    private val SECOND_LEVEL = setOf("co", "com", "net", "org", "gov", "ac", "edu", "or", "ne")

    fun match(
        candidates: List<AutofillCandidate>,
        packageName: String?,
        webDomain: String?,
        ownPackage: String? = null,
        limit: Int = DEFAULT_LIMIT,
    ): List<AutofillMatch> {
        val pkg = packageName?.trim()?.lowercase()?.takeIf { it.isNotEmpty() && it != ownPackage?.lowercase() }
        val domain = webDomain?.let(::hostOf)?.takeIf { it.isNotEmpty() }
        if (pkg == null && domain == null) return emptyList()
        return candidates
            .mapNotNull { c -> kindOf(c, pkg, domain)?.let { AutofillMatch(c, it) } }
            .sortedWith(compareBy({ it.kind }, { it.candidate.issuer.lowercase() }, { it.candidate.id }))
            .take(limit)
    }

    private fun kindOf(
        c: AutofillCandidate,
        pkg: String?,
        domain: String?,
    ): MatchKind? =
        when {
            c.associations.any { explicit(it, pkg, domain) } -> MatchKind.EXPLICIT
            domain != null && issuerNamesDomain(c.issuer, domain) -> MatchKind.ISSUER_DOMAIN
            pkg != null && issuerInPackage(c.issuer, pkg) -> MatchKind.ISSUER_PACKAGE
            else -> null
        }

    /** An association is a package name (matched as written) or a domain/URL (matched with its subdomains). */
    private fun explicit(
        association: String,
        pkg: String?,
        domain: String?,
    ): Boolean {
        val a = association.trim().lowercase()
        return a.isNotEmpty() && ((pkg != null && a == pkg) || (domain != null && domainCovers(hostOf(a), domain)))
    }

    /** [parent] is [domain] or one of its parents (`example.com` covers `login.example.com`). */
    fun domainCovers(
        parent: String,
        domain: String,
    ): Boolean = parent.isNotEmpty() && (domain == parent || domain.endsWith(".$parent"))

    /** Host of a URL or bare domain: lower case, no scheme, credentials, port, path or `www.`. */
    fun hostOf(value: String): String =
        value
            .trim()
            .lowercase()
            .substringAfter("://")
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .substringAfter('@')
            .substringBefore(':')
            .removePrefix("www.")
            .trimEnd('.')

    /** `login.example.co.uk` to `example`; the label before the public suffix (a short built-in list of 2-level suffixes). */
    internal fun registrableLabel(domain: String): String? {
        val labels = domain.split('.').filter { it.isNotEmpty() }
        if (labels.size < 2) return null // a bare label has no registrable part
        val twoLevel = labels.size > 2 && labels.last().length == 2 && labels[labels.size - 2] in SECOND_LEVEL
        return labels[labels.size - (if (twoLevel) THREE else 2)]
    }

    private fun key(issuer: String) = issuer.lowercase().filter { it.isLetterOrDigit() }

    private fun issuerNamesDomain(
        issuer: String,
        domain: String,
    ): Boolean {
        val trimmed = issuer.trim().lowercase()
        if (trimmed.contains('.') && !trimmed.contains(' ')) {
            val host = hostOf(trimmed)
            if (host.contains('.') && (domainCovers(host, domain) || domainCovers(domain, host))) return true
        }
        val k = key(issuer)
        return k.length >= MIN_ISSUER && registrableLabel(domain) == k
    }

    private fun issuerInPackage(
        issuer: String,
        pkg: String,
    ): Boolean {
        val k = key(issuer)
        return k.length >= MIN_ISSUER && pkg.split('.').any { it == k && it !in GENERIC_SEGMENTS }
    }
}
