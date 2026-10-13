// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The vault's domain model, the per-item merge, and the client side of sync (M3): the /otp/v1 API
// client with Ed25519 request signing, account bootstrap and enrollment, pairing, the commit/pull
// engine with head verification, and the SSE listener. Pure Kotlin; storage is an interface
// implemented by :core:vault (Room). The contract fake server lives in the test fixtures.

plugins {
    id("uotp.jvm.library")
    `java-test-fixtures`
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":core:otp"))
    api(project(":core:crypto"))
    api(libs.kotlinx.coroutines.core)
    api(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)

    testFixturesApi(project(":core:crypto"))
    testFixturesApi(libs.okhttp.mockwebserver)
    testFixturesImplementation(libs.kotlinx.serialization.json)

    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.kotest.property)
}
