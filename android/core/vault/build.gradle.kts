// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The encrypted local vault: Room rows of item ciphertext (crypto-format.md §6.2), the vault and
// device keys wrapped by the Android Keystore, and the repository the UI and sync use.

plugins {
    id("uotp.android.library")
    alias(libs.plugins.ksp)
    alias(libs.plugins.room)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.qtekfun.ultimateotp.core.vault"
}

room3 {
    schemaDirectory("$projectDir/schemas")
}

dependencies {
    api(project(":core:sync"))
    api(project(":core:importers"))
    api(libs.room.runtime)
    ksp(libs.room.compiler)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.turbine)
}
