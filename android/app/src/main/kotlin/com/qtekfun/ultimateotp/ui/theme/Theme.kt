// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalContext
import com.qtekfun.ultimateotp.util.ThemeMode

internal val LocalStatusColors = staticCompositionLocalOf { DarkStatusColors }

/** Status colours (success, warning, danger) of the current theme. */
val MaterialTheme.status: StatusColors
    @Composable @ReadOnlyComposable
    get() = LocalStatusColors.current

/**
 * Dark-first Material 3. [dynamicColor] (Android 12+, off by default) takes the wallpaper palette;
 * [amoled] makes the dark background true black.
 */
@Composable
fun UotpTheme(
    mode: ThemeMode = ThemeMode.SYSTEM,
    amoled: Boolean = false,
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val dark =
        when (mode) {
            ThemeMode.SYSTEM -> isSystemInDarkTheme()
            ThemeMode.LIGHT -> false
            ThemeMode.DARK -> true
        }
    val context = LocalContext.current
    val colors =
        when {
            dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            }

            dark -> {
                uotpDarkColors(amoled)
            }

            else -> {
                uotpLightColors()
            }
        }
    CompositionLocalProvider(LocalStatusColors provides if (dark) DarkStatusColors else LightStatusColors) {
        MaterialTheme(colorScheme = colors, typography = UotpTypography, shapes = UotpShapes, content = content)
    }
}

/** Whether [mode] resolves to dark right now (for the system bars). */
@Composable
fun isDark(mode: ThemeMode): Boolean =
    when (mode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
