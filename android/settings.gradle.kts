// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

pluginManagement {
    // Convention plugins shared by :app and the :core modules (quality gates, SDK levels).
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "UltimateOTP"
// include(":app")
include(":core:otp")
include(":core:crypto")
include(":core:vault")
include(":core:sync")
