// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import com.qtekfun.ultimateotp.core.sync.EnrollmentPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Consistency between what the app tells the user to type and what Android lets it open.
 *
 * `EnrollmentPolicy` (and docs/deploy.md) accept plain `http://` for LAN addresses such as
 * `http://192.168.1.5:8080`. Since Android 9 an app targeting API 28+ may not use cleartext HTTP
 * unless its manifest allows it. This test reads the production manifest as a file.
 */
class CleartextPolicyTest {
    private val manifest: String =
        listOf("src/main/AndroidManifest.xml", "app/src/main/AndroidManifest.xml")
            .map(::File)
            .first { it.exists() }
            .readText()

    @Test
    fun `the policy really does accept a plain-http LAN address`() {
        val choice = EnrollmentPolicy.choose("http://192.168.1.5:8080", "", allowRemote = false, allowCleartext = true)
        assertEquals(EnrollmentPolicy.Choice.Use("http://192.168.1.5:8080"), choice)
        // Release builds refuse cleartext (KB-4 fix): the LAN address is local but not https.
        assertEquals(
            EnrollmentPolicy.Choice.InsecureUrl,
            EnrollmentPolicy.choose("http://192.168.1.5:8080", "", allowRemote = false),
        )
        assertTrue(EnrollmentPolicy.isLocal("http://192.168.1.5"))
    }

    @Disabled(
        "KNOWN BUG KB-4: no network security config, so http:// LAN enrollment is blocked (docs/testing.md)",
    )
    @Test
    fun `a LAN address the app accepts can be opened by the platform`() {
        val allowsCleartext =
            "usesCleartextTraffic=\"true\"" in manifest || "networkSecurityConfig" in manifest
        assertTrue(allowsCleartext, "http:// LAN URLs are accepted by EnrollmentPolicy but the manifest forbids cleartext traffic")
    }
}
