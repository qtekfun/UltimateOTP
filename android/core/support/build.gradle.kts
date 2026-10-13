// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Platform-independent app logic that needs no Android types: the inactivity lock policy and the
// local diagnostics log with its redaction. Pure Kotlin, tested with fake clocks and temp dirs.

plugins {
    id("uotp.jvm.library")
}
