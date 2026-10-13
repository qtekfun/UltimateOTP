// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The second device: a fresh install logs in to the account [SignUpJourneyTest] created (same
 * server process, same email and password; CI runs the two classes one after the other with an
 * uninstall in between). Email code (not required here), SRP proof of the password with
 * Argon2id parameters read from the server, vault key unwrapped, device registered, first sync,
 * and the codes screen.
 */
@RunWith(AndroidJUnit4::class)
class LoginJourneyTest {
    private val app = AppDriver()

    @Test
    fun logInWithEmailAndPasswordOnASecondInstall() {
        app.launch()
        app.waitFor("Log in")
        app.assertAlive("first-run screen")
        app.tap("Log in")

        app.waitFor("Send code")
        app.fill(0, app.serverUrl)
        app.fill(1, app.email)
        app.tap("Send code")

        // No emailed code on this server: straight to the password.
        app.waitFor("Sign in")
        app.assertAlive("after Send code")
        app.fill(0, app.password)
        app.tap("Sign in")

        app.waitFor("Signed in. This device now syncs with your account.", AppDriver.DERIVE_MS)
        app.assertAlive("after Sign in")
        app.tap("OK")
        app.waitFor("UltimateOTP")
        assertTrue("the account is not empty, the codes screen has loaded", !app.has("Sign in"))
        app.assertAlive("codes screen")
    }
}
