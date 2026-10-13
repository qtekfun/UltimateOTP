// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PasswordStrengthTest {
    @Test
    fun `short, common and repetitive passwords are refused`() {
        assertEquals(PasswordStrength.TOO_SHORT, PasswordStrength.of("Ab1!xyz"))
        assertEquals(PasswordStrength.WEAK, PasswordStrength.of("password123"))
        assertEquals(PasswordStrength.WEAK, PasswordStrength.of("aaaaaaaaaaaaaaaaaaaa"))
        assertEquals(PasswordStrength.WEAK, PasswordStrength.of("abcdefgh"))
        assertFalse(PasswordStrength.of("abcdefgh").acceptable)
    }

    @Test
    fun `longer and more varied passwords are accepted`() {
        assertEquals(PasswordStrength.FAIR, PasswordStrength.of("Abcdefg1!"))
        assertEquals(PasswordStrength.STRONG, PasswordStrength.of("correct horse battery staple"))
        assertEquals(PasswordStrength.STRONG, PasswordStrength.of("Tr0ub4dor&3x"))
        assertTrue(PasswordStrength.of("Abcdefg1!").acceptable)
    }
}
