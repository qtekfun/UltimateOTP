// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.buildlogic

import app.cash.licensee.LicenseeExtension
import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import kotlinx.kover.gradle.plugin.dsl.KoverProjectExtension
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedComponentResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.withType
import org.jlleitschuh.gradle.ktlint.KtlintExtension

/**
 * Google Play Services and Play Core, Firebase, and every crash-reporting, analytics or telemetry
 * SDK: banned outright. Group ids, matched whole or as a parent (`io.sentry` also bans
 * `io.sentry.android`, but `io.fabric` does not ban `io.fabric8`).
 */
private val FORBIDDEN_GROUPS =
    listOf(
        "com.google.android.gms",
        "com.google.android.play",
        "com.google.firebase",
        "com.google.mlkit",
        "com.crashlytics",
        "io.fabric",
        "io.sentry",
        "ch.acra",
        "com.bugsnag",
        "com.datadoghq",
        "com.newrelic",
        "com.mixpanel",
        "com.posthog",
        "com.segment",
        "com.rollbar",
        "io.opentelemetry",
    )

/** What ships and what runs in tests. A missing one fails the check instead of being skipped. */
private fun androidClasspaths(unitTestVariant: String) =
    listOf(
        "debugRuntimeClasspath",
        "releaseRuntimeClasspath",
        "${unitTestVariant}UnitTestRuntimeClasspath",
    )

private val JVM_CLASSPATHS = listOf("runtimeClasspath", "testRuntimeClasspath")

/** True if the module (group:name) belongs to a forbidden group or one of its subgroups. */
internal fun isForbidden(module: String): Boolean {
    val group = module.substringBefore(':')
    return FORBIDDEN_GROUPS.any { group == it || group.startsWith("$it.") }
}

internal val Project.libs: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("libs")

/**
 * The quality gates every module shares: detekt, ktlint, licensee, the forbidden-dependency
 * check (all wired into `check`) and JUnit 5 (plus the vintage engine for Robolectric's JUnit 4
 * runner) for unit tests.
 */
internal fun Project.configureQuality(
    android: Boolean,
    /** The build type whose unit tests exist: AGP creates them for the module's `testBuildType` only. */
    unitTestVariant: String = "debug",
) {
    with(pluginManager) {
        apply("io.gitlab.arturbosch.detekt")
        apply("org.jlleitschuh.gradle.ktlint")
        apply("app.cash.licensee")
        apply("org.jetbrains.kotlinx.kover")
    }

    extensions.configure<DetektExtension> {
        buildUponDefaultConfig = true
        allRules = false
        config.setFrom(isolated.rootProject.projectDirectory.file("config/detekt/detekt.yml"))
        source.setFrom(
            "src/main/java",
            "src/main/kotlin",
            "src/debug/java",
            "src/test/java",
            "src/test/kotlin",
            "src/testFixtures/kotlin",
        )
    }
    tasks.withType<Detekt>().configureEach {
        // Match the project bytecode level; detekt defaults to the JDK running Gradle.
        jvmTarget = JVM_TARGET.target
    }

    extensions.configure<KtlintExtension> {
        version.set(libs.findVersion("ktlint").get().requiredVersion)
    }

    // Only GPL-3.0-compatible free licenses may ship. Anything else, including dependencies
    // without a declared license, fails the build.
    extensions.configure<LicenseeExtension> {
        allow("Apache-2.0")
        allow("MIT")
        allow("BSD-3-Clause")
        // JNA (dual LGPL-2.1+/Apache-2.0) and the libsodium loader on the JVM test classpath.
        allow("LGPL-2.1-or-later")
        allow("MPL-2.0")
        // libsodium's ISC license, as published in the bindings' POM.
        allow("ISC")
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
    with(dependencies) {
        add("testImplementation", platform(libs.findLibrary("junit-bom").get()))
        add("testImplementation", libs.findLibrary("junit-jupiter").get())
        add("testRuntimeOnly", libs.findLibrary("junit-vintage-engine").get())
        add("testRuntimeOnly", libs.findLibrary("junit-platform-launcher").get())
    }

    registerForbiddenDependencyCheck(if (android) androidClasspaths(unitTestVariant) else JVM_CLASSPATHS)
    configureCoverage()
}

/**
 * Classes that are not production code: generated ones (Hilt and Dagger factories and
 * components, Room's `_Impl`, the Compose compiler's singletons, `R`, `BuildConfig`) and the
 * test fixtures of `:core:sync`.
 */
private val EXCLUDED_FROM_COVERAGE =
    listOf(
        "*.BuildConfig",
        "*.R",
        "*.R$*",
        "*_Factory",
        "*_Factory$*",
        "*_HiltModules*",
        "*_HiltComponents*",
        "*_GeneratedInjector",
        "*_MembersInjector",
        "Hilt_*",
        "hilt_aggregated_deps.*",
        "dagger.hilt.internal.aggregatedroot.codegen.*",
        "*_Impl",
        "*_Impl$*",
        "*ComposableSingletons*",
        // The contract fake server and in-memory store are test code that lives in testFixtures.
        "com.qtekfun.ultimateotp.core.sync.fake.*",
    )

/**
 * Line coverage that only goes up: `./gradlew koverVerify` (part of `check`) fails below the
 * module's floor in `config/coverage/thresholds.properties`. The floors are measured values
 * minus a small margin, never targets (docs/testing.md).
 */
private fun Project.configureCoverage() {
    val thresholds =
        providers.fileContents(isolated.rootProject.projectDirectory.file("config/coverage/thresholds.properties"))
    // `:core:otp` is `core.otp` (a colon would be a separator in .properties files).
    val key = path.removePrefix(":").replace(':', '.')
    val floor =
        java.util
            .Properties()
            .apply {
                thresholds.asText.orNull
                    ?.reader()
                    ?.use { load(it) }
            }.getProperty(key)
            ?.toInt()
            ?: throw GradleException("config/coverage/thresholds.properties has no line for $key ($path)")
    extensions.configure<KoverProjectExtension> {
        reports {
            filters {
                excludes {
                    classes(EXCLUDED_FROM_COVERAGE)
                }
            }
            verify {
                rule("line coverage of $path") {
                    minBound(floor)
                }
            }
        }
    }
}

private fun Project.registerForbiddenDependencyCheck(names: List<String>) {
    val check =
        tasks.register("checkForbiddenDependencies") {
            group = "verification"
            description = "Fails if a runtime or test classpath contains Play Services, Firebase " +
                "or a crash-reporting, analytics or telemetry SDK."
            val roots =
                names.map { name ->
                    configurations.named(name).flatMap { it.incoming.resolutionResult.rootComponent }
                }
            doLast {
                logger.lifecycle("checkForbiddenDependencies scanned ${names.joinToString()}")
                val offenders = modulesOf(roots.map { it.get() }).filter(::isForbidden).sorted()
                if (offenders.isNotEmpty()) {
                    throw GradleException(
                        "Forbidden non-free dependencies found: ${offenders.joinToString()}",
                    )
                }
            }
        }
    tasks.named("check") { dependsOn(check) }
}

/** Every external module (group:name) reachable from [roots]. */
private fun modulesOf(roots: List<ResolvedComponentResult>): Set<String> {
    val modules = mutableSetOf<String>()
    val seen = mutableSetOf<ResolvedComponentResult>()
    val pending = ArrayDeque(roots)
    while (pending.isNotEmpty()) {
        val component = pending.removeFirst()
        if (seen.add(component)) {
            (component.id as? ModuleComponentIdentifier)?.let {
                modules.add(it.moduleIdentifier.toString())
            }
            component.dependencies
                .filterIsInstance<ResolvedDependencyResult>()
                .forEach { pending.add(it.selected) }
        }
    }
    return modules
}
