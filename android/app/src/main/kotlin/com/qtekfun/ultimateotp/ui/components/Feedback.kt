// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.ui.theme.status
import com.qtekfun.ultimateotp.util.PasswordStrength

/** What a [Callout] means; every kind also has its own icon, so colour is never the only signal. */
enum class CalloutKind { INFO, WARNING, ERROR, SUCCESS }

/** A bordered message card: an icon, an optional bold title and a body. */
@Composable
fun Callout(
    text: String,
    modifier: Modifier = Modifier,
    kind: CalloutKind = CalloutKind.INFO,
    title: String? = null,
    icon: ImageVector? = null,
) {
    val (kindIcon, accent) = calloutStyle(kind)
    Surface(
        modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = accent.copy(alpha = 0.12f),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.45f)),
    ) {
        Row(Modifier.padding(Space.Lg), horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
            Icon(icon ?: kindIcon, contentDescription = null, tint = accent, modifier = Modifier.size(24.dp))
            Column(verticalArrangement = Arrangement.spacedBy(Space.Xs)) {
                if (title != null) Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            }
        }
    }
}

@Composable
private fun calloutStyle(kind: CalloutKind): Pair<ImageVector, Color> =
    when (kind) {
        CalloutKind.INFO -> Icons.Filled.Info to MaterialTheme.colorScheme.secondary
        CalloutKind.WARNING -> Icons.Filled.WarningAmber to MaterialTheme.status.warning
        CalloutKind.ERROR -> Icons.Filled.ErrorOutline to MaterialTheme.status.danger
        CalloutKind.SUCCESS -> Icons.Filled.CheckCircle to MaterialTheme.status.success
    }

private const val SEGMENTS = 4

/** A password strength bar of four segments with the verdict in words next to an icon. */
@Composable
fun StrengthMeter(
    strength: PasswordStrength,
    modifier: Modifier = Modifier,
) {
    val filled =
        when (strength) {
            PasswordStrength.TOO_SHORT -> 1
            PasswordStrength.WEAK -> 2
            PasswordStrength.FAIR -> 3
            PasswordStrength.STRONG -> SEGMENTS
        }
    val color =
        when (strength) {
            PasswordStrength.TOO_SHORT, PasswordStrength.WEAK -> MaterialTheme.status.danger
            PasswordStrength.FAIR -> MaterialTheme.status.warning
            PasswordStrength.STRONG -> MaterialTheme.status.success
        }
    val text =
        stringResource(
            when (strength) {
                PasswordStrength.TOO_SHORT -> R.string.strength_too_short
                PasswordStrength.WEAK -> R.string.strength_weak
                PasswordStrength.FAIR -> R.string.strength_fair
                PasswordStrength.STRONG -> R.string.strength_strong
            },
        )
    Column(
        modifier.fillMaxWidth().semantics(mergeDescendants = true) {
            stateDescription = text
        },
        verticalArrangement = Arrangement.spacedBy(Space.Sm),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(Space.Xs)) {
            repeat(SEGMENTS) { index ->
                Box(
                    Modifier
                        .weight(1f)
                        .height(6.dp)
                        .clip(CircleShape)
                        .background(if (index < filled) color else MaterialTheme.colorScheme.surfaceContainerHighest),
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(Space.Sm), verticalAlignment = Alignment.Top) {
            Icon(
                if (strength.acceptable) Icons.Filled.CheckCircle else Icons.Filled.WarningAmber,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(18.dp),
            )
            Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Small round tinted badge around an icon, used for step headers and list rows. */
@Composable
fun IconBadge(
    icon: ImageVector,
    modifier: Modifier = Modifier,
    tint: Color = MaterialTheme.colorScheme.primary,
    container: Color = tint.copy(alpha = 0.14f),
    size: androidx.compose.ui.unit.Dp = 40.dp,
) {
    Box(modifier.size(size).clip(RoundedCornerShape(size * 0.32f)).background(container), contentAlignment = Alignment.Center) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
    }
}
