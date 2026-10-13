// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.core.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

class CryptoResourcesTest {
    @Test
    fun `the bundled data files load through the absolute path`() {
        assertEquals(Bip39.WORDS, Bip39.wordlist.size)
        assertEquals(4096, SrpGroup.RFC5054_4096.n.bitLength())
    }

    /**
     * R8 repackages classes, so a resource name relative to a class resolves in debug builds and unit
     * tests but is `null` in the minified release app (the 0.1.2 sign-up crash). Only absolute names
     * ("/com/...") survive. Walk every main source set of the project and refuse the relative form.
     */
    @Test
    fun `no main source reads a resource relative to a class`() {
        val root =
            generateSequence(File("").absoluteFile) { it.parentFile }
                .firstOrNull { File(it, "settings.gradle.kts").isFile }
        assertNotNull(root, "settings.gradle.kts not found above ${File("").absolutePath}")
        val dir: File = root!!
        val relative = Regex("""getResource(AsStream)?\(\s*"(?!/)""")
        val offenders =
            dir
                .walkTopDown()
                .onEnter { it.name != "build" && it.name != ".gradle" && it.name != ".git" }
                .filter { it.isFile && it.extension == "kt" && "/src/main/" in it.path }
                .filter { relative.containsMatchIn(it.readText()) }
                .map { it.relativeTo(dir).path }
                .toList()
        assertTrue(offenders.isEmpty(), "relative resource lookups break under R8: $offenders")
    }
}
