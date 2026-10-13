// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Pure Kotlin: TOTP/HOTP/Steam generation and otpauth:// / otpauth-migration:// parsing.
// No Android types, no dependencies beyond the JDK (javax.crypto.Mac).

plugins {
    id("uotp.jvm.library")
}
