// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.buildlogic

import com.android.build.api.dsl.ApplicationExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

/** `uotp.android.application`: the app module, with Compose and the shared quality gates. */
class AndroidApplicationConventionPlugin : Plugin<Project> {
    private companion object {
        const val TEST_BUILD_TYPE_PROPERTY = "uotp.testBuildType"
        const val DEFAULT_TEST_BUILD_TYPE = "smoke"
    }

    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("com.android.application")
            pluginManager.apply("org.jetbrains.kotlin.plugin.compose")

            // Instrumented tests (emulator, CI) target the minified `smoke` build type, which is
            // the release build under a debug signature (app/build.gradle.kts); that is also the
            // variant whose unit tests run. `-Puotp.testBuildType=debug` selects the debug build
            // instead (the KDF instrumented test runs unminified, docs/testing.md).
            val testBuildType = providers.gradleProperty(TEST_BUILD_TYPE_PROPERTY).getOrElse(DEFAULT_TEST_BUILD_TYPE)

            extensions.configure<ApplicationExtension> {
                configureAndroid(this)
                this.testBuildType = testBuildType
                defaultConfig.targetSdk = TARGET_SDK
                buildFeatures.compose = true

                // Reproducible builds (F-Droid): no Google-encrypted dependency blob in the APK.
                dependenciesInfo.apply {
                    includeInApk = false
                    includeInBundle = false
                }

                androidResources.generateLocaleConfig = true
            }

            configureQuality(android = true, unitTestVariant = testBuildType)
        }
    }
}
