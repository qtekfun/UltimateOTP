// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.ui.icons.IssuerIcons
import com.qtekfun.ultimateotp.ui.icons.IssuerVisual

private const val TILE_RADIUS = 0.3f
private const val GLYPH_SHARE = 0.54f
private const val LETTER_SHARE = 0.46f
private const val LIGHT_BRAND = 0.55f
private const val DARK_BRAND = 0.04f

/**
 * The logo of an account's issuer: a bundled brand mark on the brand colour, or a coloured letter.
 * Decorative (the card carries the name), so it has no content description.
 */
@Composable
fun IssuerAvatar(
    issuer: String,
    label: String,
    modifier: Modifier = Modifier,
    iconKey: String? = null,
    size: Dp = 48.dp,
) {
    val visual = remember(issuer, label, iconKey) { IssuerIcons.visualFor(issuer, label, iconKey) }
    val shape = RoundedCornerShape(size * TILE_RADIUS)
    if (issuer.isBlank() && label.isBlank() && iconKey == null) {
        // Nothing typed yet: a neutral tile with a key, not a letter on a random colour.
        Box(
            modifier.size(size).clip(shape).background(MaterialTheme.colorScheme.surfaceContainerHighest),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Filled.Key,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(size * GLYPH_SHARE),
            )
        }
        return
    }
    when (visual) {
        is IssuerVisual.Brand -> {
            val tile = Color(0xFF000000.toInt() or visual.brand)
            val glyph = if (tile.luminance() > LIGHT_BRAND) Color(0xFF111418) else Color.White
            val border =
                if (tile.luminance() < DARK_BRAND) {
                    Modifier.border(BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant), shape)
                } else {
                    Modifier
                }
            Box(
                modifier
                    .size(size)
                    .clip(shape)
                    .background(tile)
                    .then(border),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    painterResource(visual.drawable),
                    contentDescription = null,
                    tint = glyph,
                    modifier = Modifier.size(size * GLYPH_SHARE),
                )
            }
        }

        is IssuerVisual.Letter -> {
            val tile = Color(visual.argb)
            val text = if (tile.luminance() > LIGHT_BRAND) Color(0xFF111418) else Color.White
            Box(modifier.size(size).clip(shape).background(tile), contentAlignment = Alignment.Center) {
                Text(
                    visual.letter,
                    color = text,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = with(LocalDensity.current) { (size * LETTER_SHARE).toSp() },
                )
            }
        }
    }
}
