// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.icons

import androidx.annotation.DrawableRes
import java.text.Normalizer
import java.util.Locale

/** A bundled brand icon: a vector drawable resource, the brand colour (0xRRGGBB) and the brand's name. */
internal data class IssuerIcon(
    @DrawableRes val drawable: Int,
    val brand: Int,
    val title: String,
)

/** What to draw for an account: a brand icon, or a coloured letter. */
sealed interface IssuerVisual {
    /** [brand] is 0xRRGGBB. */
    data class Brand(
        @DrawableRes val drawable: Int,
        val brand: Int,
        val title: String,
    ) : IssuerVisual

    /** [argb] is a stable colour derived from the name; [brand] is true when it is the brand's own. */
    data class Letter(
        val letter: String,
        val argb: Int,
        val brand: Boolean = false,
    ) : IssuerVisual
}

/**
 * Finds the icon of an issuer. Everything is plain Kotlin on strings, so it is testable on the JVM:
 * `GitHub`, `github.com`, `GitHub Inc.` and `accounts.github.com` are the same issuer.
 */
object IssuerIcons {
    /** Simple Icons slugs a name resolves to when it differs from the slug itself (keys are squashed names). */
    private val ALIASES: Map<String, String> =
        mapOf(
            "twitter" to "x",
            "xcorp" to "x",
            "meta" to "facebook",
            "fb" to "facebook",
            "gmail" to "google",
            "googleaccount" to "google",
            "googlemail" to "google",
            "youtubemusic" to "youtube",
            "gcp" to "googlecloud",
            "googlecloudplatform" to "googlecloud",
            "chrome" to "googlechrome",
            "appleid" to "apple",
            "applecomputer" to "apple",
            "digital" to "digitalocean",
            "digitaloceanspaces" to "digitalocean",
            "npmjs" to "npm",
            "npmregistry" to "npm",
            "pythonpackageindex" to "pypi",
            "dockerhub" to "docker",
            "hetzneronline" to "hetzner",
            "hetznercloud" to "hetzner",
            "ovhcloud" to "ovh",
            "ovhtelecom" to "ovh",
            "pm" to "protonmail",
            "protonaccount" to "proton",
            "bitwardenvault" to "bitwarden",
            "blockchain" to "blockchaindotcom",
            "itch" to "itchdotio",
            "gog" to "gogdotcom",
            "battle" to "battledotnet",
            "battlenet" to "battledotnet",
            "blizzard" to "battledotnet",
            "epic" to "epicgames",
            "psn" to "playstation",
            "playstationnetwork" to "playstation",
            "humble" to "humblebundle",
            "riot" to "riotgames",
            "claude" to "anthropic",
            "transferwise" to "wise",
            "1and1" to "ionos",
            "tutanota" to "tuta",
            "pia" to "privateinternetaccess",
            "srht" to "sourcehut",
            "hubspotcrm" to "hubspot",
            "keepass" to "keepassxc",
            "arch" to "archlinux",
            "redhatenterprise" to "redhat",
            "htb" to "hackthebox",
            "hugging" to "huggingface",
            "atlassiancloud" to "atlassian",
            "bitbucketcloud" to "bitbucket",
            "firefoxaccount" to "firefox",
            "mozillafirefox" to "firefox",
            "icloudmail" to "icloud",
            "ubuntuone" to "ubuntu",
            "canonical" to "ubuntu",
            "googleauthenticator" to "google",
            "stripedashboard" to "stripe",
            "enteauth" to "ente",
        )

    /** Brands Simple Icons no longer ships: a letter on the brand's colour (0xRRGGBB) instead of the mark. */
    private val BRAND_ONLY: Map<String, Pair<String, Int>> =
        mapOf(
            "microsoft" to ("M" to 0x0078D4),
            "outlook" to ("O" to 0x0078D4),
            "hotmail" to ("H" to 0x0078D4),
            "live" to ("L" to 0x0078D4),
            "office365" to ("O" to 0xD83B01),
            "azure" to ("A" to 0x0078D4),
            "microsoftazure" to ("A" to 0x0078D4),
            "onedrive" to ("O" to 0x0078D4),
            "xbox" to ("X" to 0x107C10),
            "amazon" to ("a" to 0xFF9900),
            "aws" to ("A" to 0xFF9900),
            "amazonwebservices" to ("A" to 0xFF9900),
            "linkedin" to ("in" to 0x0A66C2),
            "slack" to ("S" to 0x4A154B),
            "skype" to ("S" to 0x00AFF0),
            "heroku" to ("H" to 0x430098),
            "salesforce" to ("S" to 0x00A1E0),
            "oracle" to ("O" to 0xF80000),
            "ibm" to ("I" to 0x1F70C1),
            "adobe" to ("A" to 0xFA0F00),
            "yahoo" to ("Y" to 0x6001D2),
            "openai" to ("O" to 0x10A37F),
            "chatgpt" to ("C" to 0x10A37F),
            "kraken" to ("K" to 0x7132F5),
            "bitstamp" to ("B" to 0x009F4D),
            "bitfinex" to ("B" to 0x16B157),
            "bybit" to ("B" to 0xF7A600),
            "gemini" to ("G" to 0x00DCFA),
            "ledger" to ("L" to 0x000000),
            "metamask" to ("M" to 0xF6851B),
            "cryptocom" to ("C" to 0x002D74),
            "linode" to ("L" to 0x00A95C),
            "akamai" to ("A" to 0x0096D6),
            "fastmail" to ("F" to 0x0067B9),
            "twilio" to ("T" to 0xF22F46),
            "sendgrid" to ("S" to 0x1A82E2),
            "docusign" to ("D" to 0xFFCC22),
            "authy" to ("A" to 0xEC1C24),
            "duo" to ("D" to 0x6BBE4B),
            "canva" to ("C" to 0x00C4CC),
            "booking" to ("B" to 0x003B95),
            "walmart" to ("W" to 0x0071CE),
            "nintendo" to ("N" to 0xE60012),
            "minecraft" to ("M" to 0x62B47A),
            "onepassword" to ("1" to 0x0572EC),
            "ivpn" to ("I" to 0x3F6EDD),
            "windscribe" to ("W" to 0x1A2E4B),
            "pcloud" to ("p" to 0x17BED0),
        )

    private val SUFFIX_WORDS =
        setOf("inc", "llc", "ltd", "limited", "corp", "corporation", "gmbh", "co", "company", "sa", "ab", "ag", "plc", "bv", "oy", "sas")
    private val SECOND_LEVEL = setOf("co", "com", "org", "net", "gov", "edu", "ac")
    private val DOMAIN = Regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$")
    private const val MIN_FIRST_WORD = 3

    /** A name reduced to lowercase letters and digits: accents, case, spaces and punctuation gone. */
    fun squash(raw: String): String {
        val decomposed = Normalizer.normalize(raw, Normalizer.Form.NFD)
        return decomposed.filter { it.isLetterOrDigit() }.lowercase(Locale.ROOT)
    }

    /** The key a name resolves to (a Simple Icons slug or a brand-only key), or null if unknown. */
    fun keyFor(name: String): String? {
        val cleaned = name.trim().lowercase(Locale.ROOT)
        val words =
            cleaned
                .replace(Regex("\\(.*?\\)"), " ")
                .split(Regex("[^\\p{L}\\p{N}]+"))
                .filter { it.isNotEmpty() && it !in SUFFIX_WORDS }
        val first = words.firstOrNull()?.takeIf { words.size > 1 && it.length >= MIN_FIRST_WORD }
        // Most specific first: the service label of a domain, the whole name, then its first word.
        return sequence {
            domainCandidates(cleaned).forEach { yield(squash(it)) }
            yield(words.joinToString(""))
            first?.let { yield(squash(it)) }
        }.firstNotNullOfOrNull { resolveKey(it) }
    }

    private fun domainCandidates(cleaned: String): List<String> {
        if (!DOMAIN.matches(cleaned)) return emptyList()
        val labels = cleaned.split('.').dropLast(1).toMutableList()
        while (labels.size > 1 && labels.last() in SECOND_LEVEL) labels.removeAt(labels.lastIndex)
        return labels.asReversed()
    }

    private fun resolveKey(squashed: String): String? =
        when {
            squashed.isEmpty() -> null
            squashed in ALIASES -> ALIASES.getValue(squashed)
            squashed in SIMPLE_ICONS -> squashed
            squashed in BRAND_ONLY -> squashed
            else -> null
        }

    /**
     * The visual of an account. [iconKey] is an explicit choice stored with the item (a slug), then the issuer,
     * then the label's own issuer prefix (`GitHub:me@x.org`), else a letter on a colour that depends only on the name.
     */
    fun visualFor(
        issuer: String,
        label: String = "",
        iconKey: String? = null,
    ): IssuerVisual {
        val key =
            iconKey?.let { keyFor(it) }
                ?: keyFor(issuer)
                ?: label.substringBefore(':', "").takeIf { it.isNotBlank() }?.let { keyFor(it) }
        val brand = key?.let { SIMPLE_ICONS[it] }
        val brandOnly = key?.let { BRAND_ONLY[it] }
        val name = issuer.ifBlank { label }.trim()
        return when {
            brand != null -> IssuerVisual.Brand(brand.drawable, brand.brand, brand.title)
            brandOnly != null -> IssuerVisual.Letter(brandOnly.first, 0xFF000000.toInt() or brandOnly.second, brand = true)
            else -> IssuerVisual.Letter(initial(name), letterColor(name))
        }
    }

    /** First letter or digit of [name], upper-cased; `?` for an empty name. */
    fun initial(name: String): String {
        val c = name.firstOrNull { it.isLetterOrDigit() } ?: return "?"
        return c.toString().uppercase(Locale.ROOT)
    }

    private val LETTER_COLORS =
        intArrayOf(
            0xFF3B6FD4.toInt(),
            0xFF0F8A7D.toInt(),
            0xFF7A4BC9.toInt(),
            0xFFC2410C.toInt(),
            0xFFB4235A.toInt(),
            0xFF2F855A.toInt(),
            0xFF8A5A00.toInt(),
            0xFF1F7A9C.toInt(),
            0xFF5B5FC7.toInt(),
            0xFFB03A2E.toInt(),
            0xFF6B7A12.toInt(),
            0xFF4F5D75.toInt(),
        )

    private const val FNV_OFFSET = -0x7ee3623b
    private const val FNV_PRIME = 16777619

    /** A colour from a fixed palette by FNV-1a of the squashed name: the same on every device and run. */
    fun letterColor(name: String): Int {
        var hash = FNV_OFFSET
        squash(name).forEach { ch ->
            hash = (hash xor ch.code) * FNV_PRIME
        }
        return LETTER_COLORS[Math.floorMod(hash, LETTER_COLORS.size)]
    }
}
