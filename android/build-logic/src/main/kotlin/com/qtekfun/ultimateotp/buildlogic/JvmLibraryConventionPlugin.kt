// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.buildlogic

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

/**
 * `uotp.jvm.library`: pure Kotlin modules with no Android types (`:core:otp`, `:core:crypto`,
 * `:core:sync`), so later desktop/CLI clients can reuse them (design.md §4.7).
 */
class JvmLibraryConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("org.jetbrains.kotlin.jvm")
            pluginManager.apply("java-library")

            extensions.configure<JavaPluginExtension> {
                sourceCompatibility = JAVA_VERSION
                targetCompatibility = JAVA_VERSION
            }
            extensions.configure<KotlinJvmProjectExtension> {
                compilerOptions {
                    jvmTarget.set(JVM_TARGET)
                    allWarningsAsErrors.set(true)
                }
            }

            configureQuality(android = false)
        }
    }
}
