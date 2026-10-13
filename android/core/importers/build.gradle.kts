// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Readers for other authenticator apps' export files (Aegis, 2FAS, andOTP, Raivo, Bitwarden,
// Proton Authenticator): pure Kotlin, JDK crypto plus :core:crypto for scrypt and Argon2id.
// No Android types, nothing is logged, and no message ever carries file content.

plugins {
    id("uotp.jvm.library")
}

dependencies {
    api(project(":core:otp"))
    api(project(":core:crypto"))
    implementation(libs.kotlinx.serialization.json)
}
