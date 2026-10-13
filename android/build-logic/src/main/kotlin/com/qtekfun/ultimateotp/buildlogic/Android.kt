// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.buildlogic

import com.android.build.api.dsl.CommonExtension
import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinAndroidProjectExtension
import java.io.File

internal const val COMPILE_SDK = 37
internal const val TARGET_SDK = 37

/** Android 8.0: the Keystore features the vault needs (AES-GCM keys, user authentication). */
internal const val MIN_SDK = 26
internal val JVM_TARGET = JvmTarget.JVM_17
internal val JAVA_VERSION = JavaVersion.VERSION_17

/**
 * What every Android module shares: SDK levels, Java/Kotlin 17 bytecode, Kotlin and Lint
 * warnings as errors, Robolectric-friendly unit tests.
 */
internal fun Project.configureAndroid(android: CommonExtension) {
    android.apply {
        compileSdk = COMPILE_SDK
        defaultConfig.minSdk = MIN_SDK

        compileOptions.apply {
            sourceCompatibility = JAVA_VERSION
            targetCompatibility = JAVA_VERSION
        }

        lint.apply {
            warningsAsErrors = true
            abortOnError = true
            checkReleaseBuilds = true
            // A string without its translation must not ship.
            error += "MissingTranslation"
        }

        // Robolectric reads the merged resources and manifest.
        testOptions.unitTests.isIncludeAndroidResources = true
    }

    extensions.configure<KotlinAndroidProjectExtension> {
        compilerOptions {
            jvmTarget.set(JVM_TARGET)
            allWarningsAsErrors.set(true)
        }
    }

    useJvmLibsodiumInUnitTests()
    android.sourceSets
        .getByName("test")
        .kotlin.directories
        .add(testGuardDir().path)

    // Robolectric's FileDescriptor interceptor reflects into java.io, closed by default since JDK 17,
    // and SDK 36 shared memory reaches jdk.internal.access.
    tasks.withType<Test>().configureEach {
        jvmArgs(
            "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--add-exports=java.base/jdk.internal.access=ALL-UNNAMED",
        )
    }
}

/**
 * Local unit tests (JVM, Robolectric) cannot load the Android `libsodium.so` of the bindings'
 * Android variant: swap it for the JVM variant, which bundles libsodium for the host, on every
 * unit-test runtime classpath. Compilation still sees the same API.
 */
private fun Project.useJvmLibsodiumInUnitTests() {
    val jvmBindings =
        libs.findLibrary("libsodium-bindings").get().map {
            "${it.module.group}:${it.module.name}-jvm:${it.versionConstraint.requiredVersion}"
        }
    configurations.configureEach {
        if (name.endsWith("UnitTestRuntimeClasspath")) {
            exclude(mapOf("group" to "com.ionspin.kotlin", "module" to "multiplatform-crypto-libsodium-bindings-android"))
            exclude(mapOf("group" to "com.ionspin.kotlin", "module" to "multiplatform-crypto-libsodium-bindings-android-debug"))
        }
    }
    dependencies.add("testRuntimeOnly", jvmBindings)
}

/**
 * The guard test (`config/testguard`) joins every module's unit tests: JUnit skips a `@Test` that
 * returns a value without a word, and this fails the build instead.
 */
internal fun Project.testGuardDir(): File =
    isolated.rootProject.projectDirectory
        .dir("config/testguard")
        .asFile
