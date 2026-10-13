// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The only module that touches keys (design.md §4.1): libsodium through the ionspin Kotlin
// Multiplatform bindings, and every format of docs/crypto-format.md. Pure Kotlin, so the JVM
// unit tests run the same code (with the bindings' JVM libsodium) as the app.

plugins {
    id("uotp.jvm.library")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    compilerOptions {
        // The bindings' API is in UByteArray.
        optIn.add("kotlin.ExperimentalUnsignedTypes")
    }
}

/** The PyNaCl-generated vectors of docs/crypto-format.md §13, read by CryptoVectorsTest. */
val vectorsFile: RegularFile =
    isolated.rootProject.projectDirectory.file("../docs/crypto-vectors/vectors.json")

tasks.withType<Test>().configureEach {
    inputs.file(vectorsFile).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("vectors")
    systemProperty("uotp.vectors", vectorsFile.asFile.absolutePath)
}

dependencies {
    api(libs.libsodium.bindings)
    // JNA comes with the bindings (jar on the JVM, aar on Android); only its API is needed here,
    // to call crypto_pwhash with a byte password (see PasswordKdf).
    compileOnly(libs.jna)
    implementation(libs.kotlinx.serialization.json)
}
