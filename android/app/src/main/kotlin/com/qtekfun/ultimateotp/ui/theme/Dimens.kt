// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/** Spacing tokens: a 4 dp grid. Screens use these, never loose numbers. */
object Space {
    val Xs = 4.dp
    val Sm = 8.dp
    val Md = 12.dp
    val Lg = 16.dp
    val Xl = 24.dp
    val Xxl = 32.dp
    val Huge = 48.dp

    /** Side gutter of every screen. */
    val Gutter = 16.dp

    /** Minimum touch target (accessibility). */
    val Touch = 48.dp
}

val UotpShapes =
    Shapes(
        extraSmall = RoundedCornerShape(6.dp),
        small = RoundedCornerShape(10.dp),
        medium = RoundedCornerShape(16.dp),
        large = RoundedCornerShape(22.dp),
        extraLarge = RoundedCornerShape(30.dp),
    )

/** Widest a form or a settings list gets, so it stays readable on tablets and the inner display. */
val ContentMaxWidth = 640.dp
