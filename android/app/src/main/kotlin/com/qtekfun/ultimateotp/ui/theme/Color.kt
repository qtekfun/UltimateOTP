// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/** Brand: a green identity (emerald to mint), used for the logo, the primary actions and the countdown ring. */
object Brand {
    val Emerald = Color(0xFF1FB86A)
    val Mint = Color(0xFF8CF0B4)
    val Gradient: Brush get() = Brush.linearGradient(listOf(Emerald, Mint))
}

private val InkBackground = Color(0xFF0D1210)
private val InkSurface = Color(0xFF131A16)

/** Dark scheme on ink blue; [amoled] turns the background and base surfaces true black. */
fun uotpDarkColors(amoled: Boolean): ColorScheme =
    darkColorScheme(
        primary = Color(0xFF5BE08F),
        onPrimary = Color(0xFF00391B),
        primaryContainer = Color(0xFF0F4F2B),
        onPrimaryContainer = Color(0xFFB9F6CF),
        secondary = Color(0xFFA9CDB6),
        onSecondary = Color(0xFF123522),
        secondaryContainer = Color(0xFF284A38),
        onSecondaryContainer = Color(0xFFC5E9D1),
        tertiary = Color(0xFFFFC46B),
        onTertiary = Color(0xFF442B00),
        tertiaryContainer = Color(0xFF5F3E00),
        onTertiaryContainer = Color(0xFFFFDEA9),
        error = Color(0xFFFF8F87),
        onError = Color(0xFF4F0A06),
        errorContainer = Color(0xFF6B1A14),
        onErrorContainer = Color(0xFFFFDAD6),
        background = if (amoled) Color.Black else InkBackground,
        onBackground = Color(0xFFE6EAF0),
        surface = if (amoled) Color.Black else InkBackground,
        onSurface = Color(0xFFE6EAF0),
        surfaceVariant = Color(0xFF26302A),
        onSurfaceVariant = Color(0xFFB5C0B9),
        surfaceTint = Color(0xFF5BE08F),
        inverseSurface = Color(0xFFE6EAF0),
        inverseOnSurface = Color(0xFF1A211D),
        outline = Color(0xFF7F8B84),
        outlineVariant = Color(0xFF35413A),
        scrim = Color.Black,
        surfaceBright = Color(0xFF2A352E),
        surfaceDim = if (amoled) Color.Black else InkBackground,
        surfaceContainerLowest = if (amoled) Color.Black else Color(0xFF090D0B),
        surfaceContainerLow = if (amoled) Color(0xFF060807) else Color(0xFF101612),
        surfaceContainer = if (amoled) Color(0xFF0C100E) else InkSurface,
        surfaceContainerHigh = if (amoled) Color(0xFF141A16) else Color(0xFF1A221D),
        surfaceContainerHighest = if (amoled) Color(0xFF1A211D) else Color(0xFF222B25),
    )

fun uotpLightColors(): ColorScheme =
    lightColorScheme(
        primary = Color(0xFF0B7A3E),
        onPrimary = Color.White,
        primaryContainer = Color(0xFFC6F2D5),
        onPrimaryContainer = Color(0xFF00210E),
        secondary = Color(0xFF3F6350),
        onSecondary = Color.White,
        secondaryContainer = Color(0xFFC1ECD3),
        onSecondaryContainer = Color(0xFF002112),
        tertiary = Color(0xFF8A5100),
        onTertiary = Color.White,
        tertiaryContainer = Color(0xFFFFDDB4),
        onTertiaryContainer = Color(0xFF2B1700),
        error = Color(0xFFB3261E),
        onError = Color.White,
        errorContainer = Color(0xFFFFDAD6),
        onErrorContainer = Color(0xFF410002),
        background = Color(0xFFF4F8F5),
        onBackground = Color(0xFF131A16),
        surface = Color(0xFFF4F8F5),
        onSurface = Color(0xFF131A16),
        surfaceVariant = Color(0xFFDDE7E0),
        onSurfaceVariant = Color(0xFF404943),
        surfaceTint = Color(0xFF0B7A3E),
        inverseSurface = Color(0xFF29302B),
        inverseOnSurface = Color(0xFFEDF1F7),
        outline = Color(0xFF6B756E),
        outlineVariant = Color(0xFFC3CDC6),
        surfaceBright = Color.White,
        surfaceDim = Color(0xFFDAE1DC),
        surfaceContainerLowest = Color.White,
        surfaceContainerLow = Color(0xFFEEF3EF),
        surfaceContainer = Color(0xFFE8EEEA),
        surfaceContainerHigh = Color(0xFFE2E9E4),
        surfaceContainerHighest = Color(0xFFDCE3DE),
    )

/** Semantic colours Material 3 has no slot for. */
data class StatusColors(
    val success: Color,
    val warning: Color,
    val danger: Color,
)

val DarkStatusColors = StatusColors(success = Color(0xFF7CE9A6), warning = Color(0xFFFFC46B), danger = Color(0xFFFF8F87))
val LightStatusColors = StatusColors(success = Color(0xFF0B7A43), warning = Color(0xFF9A5A00), danger = Color(0xFFB3261E))
