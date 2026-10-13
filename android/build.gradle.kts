// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The plugins are put on the build classpath here, once, and applied by the convention plugins
// of build-logic (uotp.android.application, uotp.android.library, uotp.jvm.library).
plugins {
    base
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.hilt) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.licensee) apply false
    alias(libs.plugins.room) apply false
    alias(libs.plugins.ktlint)
}

// The root build scripts (settings and this file) are linted too.
ktlint {
    version.set(libs.versions.ktlint)
}

// `./gradlew check` also runs the checks and tests of the convention plugins.
tasks.named("check") {
    dependsOn(gradle.includedBuild("build-logic").task(":check"))
}
