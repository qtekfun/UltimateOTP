// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

plugins {
    id("uotp.android.application")
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

/** Release signing from the environment (CI secrets); without it the release APK is unsigned. */
val releaseKeystore: String? = providers.environmentVariable("UOTP_KEYSTORE_FILE").orNull

android {
    namespace = "com.qtekfun.ultimateotp"

    defaultConfig {
        applicationId = "com.qtekfun.ultimateotp"
        versionCode = 3
        versionName = "0.1.2"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = providers.environmentVariable("UOTP_KEYSTORE_PASSWORD").orNull
                keyAlias = providers.environmentVariable("UOTP_KEY_ALIAS").orNull
                keyPassword = providers.environmentVariable("UOTP_KEY_PASSWORD").orNull
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
            // The git commit is not part of the APK: a build from a source tarball must match.
            vcsInfo.include = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }

        // The release build as an emulator can run it: the same R8 configuration and resource
        // shrinking (`initWith(release)`), signed with the debug key, installed next to the real
        // app under its own package so it can never replace or wipe the owner's data. The only
        // differences are listed in src/smoke (a network security config for 10.0.2.2) and in
        // docs/testing.md. Not published, not signed with the release key.
        create("smoke") {
            initWith(getByName("release"))
            matchingFallbacks += "release"
            signingConfig = signingConfigs.getByName("debug")
            applicationIdSuffix = ".smoke"
            isDebuggable = false
        }
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        // The JNA AAR and the libsodium AAR both carry native libraries; keep them uncompressed
        // and page-aligned (16 KB devices).
        jniLibs.useLegacyPackaging = false
        // JNA still ships ABIs Android dropped long ago.
        jniLibs.excludes += listOf("lib/armeabi/**", "lib/mips/**", "lib/mips64/**")
    }
}

dependencies {
    implementation(project(":core:vault"))
    implementation(project(":core:sync"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.hilt.navigation.compose)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.biometric)

    // QR scanning: CameraX for frames, ZXing core (pure Java) for decoding. No ML Kit / Play Services.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(testFixtures(project(":core:sync")))
    // Compose UI tests on the JVM (Robolectric). The test activity is not declared in any manifest
    // (ui-test-manifest would ship in the build under test); Robolectric builds it directly.
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.compose.ui.test.junit4)

    // Instrumented tests (emulator, CI only): black-box UI Automator, see docs/testing.md.
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.uiautomator)
}

// What R8 did to the classes that are reached by name at run time (JNA binds libsodium by
// reflection on its interface and structures, Room loads `*_Impl`, the manifest names the
// application and the activity) or through generated code (kotlinx.serialization). A rule that
// stops working shows up here, on any machine, long before a phone does. Runs R8 once.
val verifyMinifiedBuild =
    tasks.register("verifyMinifiedBuild") {
        group = "verification"
        description = "Checks R8's mapping for classes that must keep their name or must survive."
        val mapping = layout.buildDirectory.file("outputs/mapping/smoke/mapping.txt")
        // R8 writes mapping.prt; the Compose mapping merge turns it into the mapping.txt read here.
        dependsOn("minifySmokeWithR8", "mergeSmokeComposeMapping")
        inputs.file(mapping)
        doLast {
            val renamedTo = mutableMapOf<String, String>()
            mapping.get().asFile.useLines { lines ->
                lines.filter { it.isNotEmpty() && !it[0].isWhitespace() && it[0] != '#' }.forEach { line ->
                    val (from, to) = line.removeSuffix(":").split(" -> ")
                    renamedTo[from] = to
                }
            }
            val mustKeepName =
                listOf(
                    "com.qtekfun.ultimateotp.UotpApplication",
                    "com.qtekfun.ultimateotp.MainActivity",
                    "com.qtekfun.ultimateotp.core.vault.db.VaultDatabase_Impl",
                    "com.ionspin.kotlin.crypto.LibsodiumInitializer",
                    "com.ionspin.kotlin.crypto.JnaLibsodiumInterface",
                    "com.sun.jna.Native",
                    "com.sun.jna.NativeLibrary",
                    "com.sun.jna.NativeLong",
                    "com.sun.jna.Pointer",
                    "com.sun.jna.Structure",
                    "com.sun.jna.Library\$Handler",
                )
            val mustSurvive =
                listOf(
                    "com.qtekfun.ultimateotp.core.crypto.PasswordKdf",
                    "com.qtekfun.ultimateotp.core.crypto.KdfParams",
                    "com.qtekfun.ultimateotp.core.sync.api.SignupRequest\$\$serializer",
                    "com.qtekfun.ultimateotp.core.sync.api.SrpVerifyRequest\$\$serializer",
                    "com.qtekfun.ultimateotp.core.sync.SyncEngine",
                    "com.qtekfun.ultimateotp.core.vault.VaultRepository",
                    "com.qtekfun.ultimateotp.sync.SyncController",
                )
            val problems =
                mustKeepName.filter { renamedTo[it] != it }.map { "$it was ${renamedTo[it]?.let { n -> "renamed to $n" } ?: "removed"}" } +
                    mustSurvive.filter { renamedTo[it] == null || renamedTo[it]!!.startsWith("R8\$\$REMOVED") }.map { "$it was removed" }
            if (problems.isNotEmpty()) {
                throw GradleException("R8 changed classes that are used by name:\n  " + problems.joinToString("\n  "))
            }
            logger.lifecycle("verifyMinifiedBuild: ${mustKeepName.size} names kept, ${mustSurvive.size} classes present")
        }
    }

tasks.named("check") { dependsOn(verifyMinifiedBuild) }
