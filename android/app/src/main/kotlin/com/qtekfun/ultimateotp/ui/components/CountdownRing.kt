// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.ui.theme.CodeFontFamily
import com.qtekfun.ultimateotp.ui.theme.status

/** How close a code is to expiring, which sets the ring colour (the seconds are always written too). */
enum class Urgency { CALM, SOON, NOW }

private const val SOON_FRACTION = 1f / 3f
private const val NOW_SECONDS = 5
private const val LAST_SIXTH = 6
private const val START_ANGLE = -90f
private const val FULL_CIRCLE = 360f
private const val SECOND_MS = 1_000
private const val TEXT_SHARE = 0.34f

/** Calm above a third of the period, soon below it, now in the last five seconds (or the last sixth). */
fun urgency(
    remainingMillis: Long,
    periodSeconds: Int,
): Urgency {
    val seconds = remainingMillis / SECOND_MS.toFloat()
    return when {
        seconds <= NOW_SECONDS.coerceAtMost(periodSeconds / LAST_SIXTH + 1) -> Urgency.NOW
        seconds / periodSeconds <= SOON_FRACTION -> Urgency.SOON
        else -> Urgency.CALM
    }
}

/**
 * A circular countdown: the arc shrinks as the code runs out, smoothly between the one-second
 * ticks, and changes colour (accent, amber, red) with the seconds written inside.
 */
@Composable
fun CountdownRing(
    remainingMillis: Long,
    periodSeconds: Int,
    modifier: Modifier = Modifier,
    size: Dp = 44.dp,
) {
    val urgency = urgency(remainingMillis, periodSeconds)
    val target =
        when (urgency) {
            Urgency.CALM -> MaterialTheme.colorScheme.primary
            Urgency.SOON -> MaterialTheme.status.warning
            Urgency.NOW -> MaterialTheme.status.danger
        }
    val color by animateColorAsState(target, label = "ring colour")
    // The target is where the arc will be one second from now; the animation fills the second.
    val nextFraction = ((remainingMillis - SECOND_MS).coerceAtLeast(0)).toFloat() / (periodSeconds * SECOND_MS)
    val fraction by animateFloatAsState(nextFraction, tween(SECOND_MS, easing = LinearEasing), label = "ring")
    val track = MaterialTheme.colorScheme.surfaceContainerHighest
    val stroke = with(LocalDensity.current) { (size / 10).toPx() }
    val seconds = ((remainingMillis + SECOND_MS - 1) / SECOND_MS).toInt()
    Box(modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(size)) {
            val inset = stroke / 2
            val arc = Size(this.size.width - stroke, this.size.height - stroke)
            drawArc(track, 0f, FULL_CIRCLE, useCenter = false, topLeft = Offset(inset, inset), size = arc, style = Stroke(stroke))
            drawArc(
                color,
                START_ANGLE,
                FULL_CIRCLE * fraction.coerceIn(0f, 1f),
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = arc,
                style = Stroke(stroke, cap = StrokeCap.Round),
            )
        }
        Text(
            seconds.toString(),
            color = if (urgency == Urgency.CALM) MaterialTheme.colorScheme.onSurfaceVariant else color,
            fontFamily = CodeFontFamily,
            fontWeight = FontWeight.Medium,
            fontSize = with(LocalDensity.current) { (size * TEXT_SHARE).toSp() },
            textAlign = TextAlign.Center,
        )
    }
}
