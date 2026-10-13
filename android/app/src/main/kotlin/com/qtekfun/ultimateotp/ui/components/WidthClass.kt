// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo

/** Material window width classes (compact below 600 dp, expanded from 840 dp). */
enum class WidthClass {
    COMPACT,
    MEDIUM,
    EXPANDED,
    ;

    companion object {
        private const val MEDIUM_FROM = 600
        private const val EXPANDED_FROM = 840

        fun of(widthDp: Int): WidthClass =
            when {
                widthDp >= EXPANDED_FROM -> EXPANDED
                widthDp >= MEDIUM_FROM -> MEDIUM
                else -> COMPACT
            }
    }
}

/** The width class of the window (not the screen: split-screen counts), which changes on fold/unfold and rotation. */
@Composable
fun currentWidthClass(): WidthClass {
    val widthPx = LocalWindowInfo.current.containerSize.width
    return WidthClass.of((widthPx / LocalDensity.current.density).toInt())
}
