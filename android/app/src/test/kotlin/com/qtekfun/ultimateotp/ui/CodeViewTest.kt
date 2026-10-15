// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.screenshots.Fixtures
import com.qtekfun.ultimateotp.ui.codes.codeView
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CodeViewTest {
    private val totp = Fixtures.items.first { it.otp.type == OtpType.TOTP && it.otp.period == 30 }
    private val hotp = Fixtures.items.first { it.otp.type == OtpType.HOTP }

    @Test
    fun `the next code is shown from the first second of the period`() {
        val periodStart = 1_700_000_040_000L
        val view = codeView(totp, periodStart + 1_000L)
        assertNotNull(view.next)
        assertTrue(view.showNext)
        assertNotEquals(view.code, view.next)
        // What the card shows next is exactly what it shows once the period turns over.
        assertEquals(view.next, codeView(totp, periodStart + 30_000L).code)
    }

    @Test
    fun `a counter based code has no next code`() {
        val view = codeView(hotp, Fixtures.NOW)
        assertNull(view.next)
        assertEquals(false, view.showNext)
    }
}
