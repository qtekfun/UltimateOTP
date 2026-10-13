# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# JNA binds libsodium by reflection on the interface and its structures.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class com.ionspin.kotlin.crypto.** { *; }
-dontwarn java.awt.**
-dontwarn com.sun.jna.**
-dontwarn org.slf4j.**
