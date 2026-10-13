// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.core.crypto

/**
 * Loads the data files bundled in this module's resources (the RFC 5054 group, the BIP-39 wordlist).
 *
 * The path is **absolute**. A bare file name passed to a class's resource lookup is resolved against
 * that class's package, and R8 renames and repackages classes in release builds:
 * the lookup then returns `null` in the minified app while it works in debug builds and in unit tests.
 * That crashed sign-up in 0.1.2 on a real phone. `CryptoResourcesTest` forbids the relative form.
 */
internal object CryptoResources {
    private const val ROOT = "/com/qtekfun/ultimateotp/core/crypto/"

    fun readText(name: String): String = open(name).bufferedReader(Charsets.UTF_8).use { it.readText() }

    fun readLines(name: String): List<String> = open(name).bufferedReader(Charsets.UTF_8).use { it.readLines() }

    private fun open(name: String) =
        requireNotNull(CryptoResources::class.java.getResourceAsStream(ROOT + name)) {
            "missing bundled resource $ROOT$name"
        }
}
