// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val Navy = Color(0xFF1F3A5F)
private val Sky = Color(0xFF9CC3F0)

/** Material 3 with dynamic color on Android 12+, the family's navy otherwise. */
@Composable
fun UotpTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors =
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                if (dark) {
                    dynamicDarkColorScheme(
                        context,
                    )
                } else {
                    dynamicLightColorScheme(context)
                }
            }

            dark -> {
                darkColorScheme(primary = Sky)
            }

            else -> {
                lightColorScheme(primary = Navy)
            }
        }
    MaterialTheme(colorScheme = colors, content = content)
}
