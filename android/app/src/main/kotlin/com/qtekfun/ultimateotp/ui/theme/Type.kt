// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.qtekfun.ultimateotp.R

/** JetBrains Mono (OFL), a variable font bundled in `res/font`: tabular figures, one width per digit. */
val CodeFontFamily: FontFamily =
    FontFamily(
        Font(
            R.font.jetbrains_mono,
            FontWeight.Medium,
            variationSettings = FontVariation.Settings(FontVariation.weight(FontWeight.Medium.weight)),
        ),
        Font(
            R.font.jetbrains_mono,
            FontWeight.SemiBold,
            variationSettings = FontVariation.Settings(FontVariation.weight(FontWeight.SemiBold.weight)),
        ),
    )

/** Text styles for one-time codes (the only place the monospaced face is used). */
object CodeStyles {
    val Large =
        TextStyle(
            fontFamily = CodeFontFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = 30.sp,
            lineHeight = 36.sp,
            letterSpacing = 0.5.sp,
            fontFeatureSettings = "tnum",
        )
    val Medium = Large.copy(fontSize = 24.sp, lineHeight = 30.sp)
    val Small = Large.copy(fontSize = 17.sp, lineHeight = 22.sp, fontWeight = FontWeight.Medium)
    val Hero = Large.copy(fontSize = 52.sp, lineHeight = 60.sp, letterSpacing = 1.sp)
}

/** The type scale: default (Roboto) with a clear hierarchy; sizes in sp so they follow the font scale. */
val UotpTypography =
    Typography(
        displaySmall = TextStyle(fontSize = 34.sp, lineHeight = 42.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.5).sp),
        headlineLarge = TextStyle(fontSize = 30.sp, lineHeight = 38.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.25).sp),
        headlineMedium = TextStyle(fontSize = 26.sp, lineHeight = 34.sp, fontWeight = FontWeight.SemiBold),
        headlineSmall = TextStyle(fontSize = 22.sp, lineHeight = 30.sp, fontWeight = FontWeight.SemiBold),
        titleLarge = TextStyle(fontSize = 20.sp, lineHeight = 28.sp, fontWeight = FontWeight.SemiBold),
        titleMedium = TextStyle(fontSize = 16.sp, lineHeight = 22.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.sp),
        titleSmall = TextStyle(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.1.sp),
        bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.2.sp),
        bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.2.sp),
        bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.3.sp),
        labelLarge = TextStyle(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.sp),
        labelMedium = TextStyle(fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.4.sp),
        labelSmall = TextStyle(fontSize = 11.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.5.sp),
    )
