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
    }

    buildFeatures {
        buildConfig = true
    }

    // Brand icons are long paths by nature; see lint.xml.
    lint {
        lintConfig = file("lint.xml")
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
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.core.splashscreen)
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
    // Screenshots of the screens on the JVM (Robolectric native graphics); test scope only.
    testImplementation(libs.roborazzi)
    testImplementation(libs.roborazzi.compose)
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(testFixtures(project(":core:sync")))
}

// The screen screenshots (src/test/.../screenshots) are written on every test run, to
// build/screenshots, for review; they are not compared against goldens (fonts differ per host).
tasks.withType<Test>().configureEach {
    systemProperty("roborazzi.test.record", "true")
}
