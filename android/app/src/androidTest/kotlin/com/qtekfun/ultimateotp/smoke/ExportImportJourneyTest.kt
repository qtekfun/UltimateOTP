// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.regex.Pattern

/**
 * Encrypted export (Argon2id + XChaCha20-Poly1305 secretstream, the same native path as the
 * vault) and the import of that file again, through the system document picker.
 *
 * This is the most fragile test of the suite, and unverified at the time it was written: the
 * picker is DocumentsUI, whose layout differs between system images. It looks for the buttons by
 * their label and for the file by name. CI runs it as its own, non-blocking step; if it fails
 * only because the picker moved, fix the selectors, not the app.
 */
@RunWith(AndroidJUnit4::class)
class ExportImportJourneyTest {
    private val app = AppDriver()

    @Test
    fun exportEncryptedThenImportTheSameFile() {
        app.launch()
        app.waitFor("Use without a server").click()
        app.waitFor("UltimateOTP")
        app.waitFor(By.desc("Add account")).click()
        app.waitFor("Paste").click()
        app.fill(0, "otpauth://totp/Smoke:bob@example.org?secret=JBSWY3DPEHPK3PXQ&issuer=Smoke")
        app.tap("Add")
        app.waitFor("bob@example.org")

        app.waitFor(By.desc("Settings")).click()
        app.tap("Encrypted export (.uotp)")
        app.waitFor("Export password (at least 8 characters)")
        app.fill(0, app.password)
        app.fill(1, app.password)
        app.tap("OK")

        // Create-document picker: the suggested name is `ultimateotp-export.uotp`; confirm with Save.
        val save = app.device.wait(Until.findObject(By.text(Pattern.compile("(?i)save"))), PICKER_MS)
        assertTrue("the document picker did not open: ${app.visibleText()}", save != null)
        save.click()
        app.waitFor("Export written", AppDriver.DERIVE_MS)
        app.assertAlive("after the export")

        // Open-document picker: pick that file again.
        app.tap("Import a file (UltimateOTP, Ente Auth, otpauth list)")
        val file = app.device.wait(Until.findObject(By.textContains("ultimateotp-export")), PICKER_MS)
        assertTrue("the exported file is not offered by the picker", file != null)
        file.click()
        app.waitFor("This file is encrypted. Password?", AppDriver.STEP_MS)
        app.fill(0, app.password)
        app.tap("OK")
        // The entry is already there: nothing new, one already present, nothing unreadable.
        app.waitFor("New: 0 · Already present: 1 · Unreadable: 0", AppDriver.DERIVE_MS)
        app.assertAlive("after the import")
    }

    private companion object {
        const val PICKER_MS = 20_000L
    }
}
