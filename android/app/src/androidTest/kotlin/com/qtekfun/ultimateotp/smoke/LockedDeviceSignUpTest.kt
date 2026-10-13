// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The same first taps on a phone that has a screen lock, which is every real phone: the Keystore
 * key that wraps the vault key is created with `setUserAuthenticationRequired(true)` and a 30 s
 * validity window, so storing the first secret needs a fresh authentication.
 *
 * The test sets a PIN (`locksettings`), waits out the window, and taps "Create account". It does
 * not require the account to be created: it requires the app to still be there, showing either
 * the next step, the system's authentication prompt, or an error the user can act on.
 *
 * Known to fail at the time of writing (docs/testing.md, KB-3), which is why CI runs it as a
 * non-blocking step. The PIN is removed afterwards.
 */
@RunWith(AndroidJUnit4::class)
class LockedDeviceSignUpTest {
    private val app = AppDriver()

    @Before
    fun setPin() {
        app.device.executeShellCommand("locksettings set-pin $PIN")
        // The key needs an authentication newer than its 30 s validity window; none has happened.
        Thread.sleep(WINDOW_MS)
    }

    @After
    fun clearPin() {
        app.device.executeShellCommand("locksettings clear --old $PIN")
    }

    @Test
    fun tappingCreateAccountDoesNotCrash() {
        app.launch()
        app.waitFor("Create account")
        app.tap("Create account")
        // Either the sign-up form, or the lock prompt, or an explanation: never a dead process.
        Thread.sleep(SETTLE_MS)
        app.assertAlive("after tapping Create account on a phone with a screen lock")
    }

    private companion object {
        const val PIN = "1234"
        const val WINDOW_MS = 35_000L
        const val SETTLE_MS = 5_000L
    }
}
