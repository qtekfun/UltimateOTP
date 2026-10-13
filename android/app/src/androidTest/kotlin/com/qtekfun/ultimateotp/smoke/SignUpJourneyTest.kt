// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What the owner did on the Pixel, as a test: install the minified release build, tap "Create
 * account", give a server, email and the emailed code, choose a password, write down the 24
 * words, confirm, and end up with an account whose codes sync. Against a real server process
 * (`UOTP_SIGNUP=enabled`, `UOTP_EMAIL_VERIFICATION=disabled`) started by the CI job.
 *
 * A crash anywhere ends the instrumentation (same process): that is the failure this test exists
 * to produce. Every step also checks the system's crash dialog and the foreground package.
 *
 * Requires a freshly installed app (Gradle installs and uninstalls it around each run).
 */
@RunWith(AndroidJUnit4::class)
class SignUpJourneyTest {
    private val app = AppDriver()

    @Test
    fun createAccountOnARealServer() {
        app.launch()

        // First run: the four choices.
        app.waitFor("Create account")
        app.assertAlive("first-run screen")
        assertTrue("sign-in choice", app.has("Log in"))
        assertTrue("offline choice", app.has("Use without a server"))

        // Tap 1 (the first crash on the phone): creating the local vault and opening the form.
        app.tap("Create account")
        app.waitFor("I already have an account: log in")
        app.assertAlive("after tapping Create account")

        // Server and email, then the code. Verification is off on this server: the code is carried, not checked.
        app.fill(0, app.serverUrl)
        app.fill(1, app.email)
        app.tap("Send code")
        app.waitFor("Next")
        app.assertAlive("after Send code")
        app.fill(0, "123456")
        app.tap("Next")

        // Password: derived on the device (Argon2id, the rung chosen from free memory), then the 24 words.
        app.waitFor("Deriving the key from your password takes a few seconds on purpose.")
        app.fill(0, app.password)
        app.fill(1, app.password)
        app.tap("Next")
        app.waitFor("Your recovery key", AppDriver.DERIVE_MS)
        app.assertAlive("after deriving the key (the second crash on the phone)")
        val words = app.visibleText()
        assertTrue("24 numbered words on screen: $words", Regex("""\b24\. \w+""").containsMatchIn(words))

        // Confirm and create: sign-up request, device keys, first sync.
        app.scrollTo("Create my account")
        app.device.findObject(By.clazz("android.widget.CheckBox")).click()
        app.tapAfterScrolling("Create my account")
        app.waitFor(
            "Account created. This phone now syncs with it; log in on other devices with your email and password.",
            AppDriver.DERIVE_MS,
        )
        app.assertAlive("after Create my account")

        app.tap("OK")
        app.waitFor("UltimateOTP")
        app.assertAlive("codes screen")
    }
}
