// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.buildlogic

import com.android.build.api.dsl.ApplicationExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

/** `uotp.android.application`: the app module, with Compose and the shared quality gates. */
class AndroidApplicationConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("com.android.application")
            pluginManager.apply("org.jetbrains.kotlin.plugin.compose")

            extensions.configure<ApplicationExtension> {
                configureAndroid(this)
                defaultConfig.targetSdk = TARGET_SDK
                buildFeatures.compose = true

                // Reproducible builds (F-Droid): no Google-encrypted dependency blob in the APK.
                dependenciesInfo.apply {
                    includeInApk = false
                    includeInBundle = false
                }

                androidResources.generateLocaleConfig = true
            }

            configureQuality(android = true)
        }
    }
}
