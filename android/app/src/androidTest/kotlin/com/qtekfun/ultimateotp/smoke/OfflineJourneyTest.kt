// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The app with no server at all: start, "Use without a server", add an entry from an `otpauth://`
 * URI (Paste tab), see its code, and open the settings. No network is involved, so this is the
 * release build's own code (R8, JNA, Room, serialization, Compose) and nothing else.
 */
@RunWith(AndroidJUnit4::class)
class OfflineJourneyTest {
    private val app = AppDriver()

    @Test
    fun startAddAnEntryAndSeeItsCode() {
        app.launch()
        app.waitFor("Use without a server")
        app.assertAlive("first-run screen")
        app.tap("Use without a server")

        app.waitFor("UltimateOTP")
        app.assertAlive("empty codes screen")
        assertTrue(app.has("No accounts yet. Tap + to scan a QR code or enter a key."))

        // Add > Paste. The floating button's description is "Add account".
        app.waitFor(By.desc("Add account")).click()
        app.waitFor("Paste").click()
        app.fill(0, "otpauth://totp/Smoke:alice@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Smoke&period=30&digits=6")
        app.tap("Add")

        // Back on the list: issuer, account and a grouped code (`123 456`).
        app.waitFor("Smoke")
        app.waitFor("alice@example.org")
        val codes =
            app.device.findObjects(
                By.text(
                    java.util.regex.Pattern
                        .compile("\\d{3} \\d{3}"),
                ),
            )
        assertTrue("a six digit code is shown: ${app.visibleText()}", codes.isNotEmpty())
        app.assertAlive("codes screen with an entry")

        // The settings screen draws; export and import are in ExportImportJourneyTest.
        app.waitFor(By.desc("Settings")).click()
        app.waitFor("Encrypted export (.uotp)")
        app.assertAlive("settings")
    }
}
