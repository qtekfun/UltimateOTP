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

// The sync engine against the real Python server (RealServerContractTest, tag "contract"): needs
// `uv`, so it is not part of `test` and `check`; CI runs it as its own job.
val serverDir: Directory = isolated.rootProject.projectDirectory.dir("../server")
val migrationsDir: Directory = isolated.rootProject.projectDirectory.dir("../contracts/db/migrations")

tasks.test {
    useJUnitPlatform { excludeTags("contract") }
}

tasks.register<Test>("contractTest") {
    group = "verification"
    description = "Runs the sync engine against `uv run ultimateotp api` (needs uv; docs/testing.md)."
    val test = sourceSets.test.get()
    testClassesDirs = test.output.classesDirs
    classpath = test.runtimeClasspath
    useJUnitPlatform { includeTags("contract") }
    inputs.dir(serverDir.dir("src")).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("serverSources")
    inputs.dir(migrationsDir).withPathSensitivity(PathSensitivity.RELATIVE).withPropertyName("migrations")
    systemProperty("uotp.server.dir", serverDir.asFile.absolutePath)
    systemProperty("uotp.migrations.dir", migrationsDir.asFile.absolutePath)
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
    shouldRunAfter(tasks.test)
}

// Kover would wire every Test task into `koverVerify`, and with it `check`; contractTest needs uv.
kover {
    currentProject {
        instrumentation {
            disabledForTestTasks.add("contractTest")
        }
    }
}
