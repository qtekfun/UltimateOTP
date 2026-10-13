// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.theme.Brand
import com.qtekfun.ultimateotp.ui.theme.Space

/** Three cards fading out, each with a logo tile, two lines and a ring: what the list will look like. */
@Composable
fun EmptyIllustration(modifier: Modifier = Modifier) {
    val outline = MaterialTheme.colorScheme.outlineVariant
    val fill = MaterialTheme.colorScheme.surfaceContainer
    val line = MaterialTheme.colorScheme.surfaceContainerHighest
    Canvas(modifier.size(width = 248.dp, height = 188.dp)) {
        fun px(value: Float) = value.dp.toPx()
        val cardW = size.width
        val cardH = px(52f)
        val gap = px(10f)
        val radius = CornerRadius(px(16f))
        repeat(3) { index ->
            val alpha = 1f - index * 0.32f
            val y = index * (cardH + gap)
            drawRoundRect(fill.copy(alpha = alpha), Offset(0f, y), Size(cardW, cardH), radius)
            drawRoundRect(outline.copy(alpha = alpha), Offset(0f, y), Size(cardW, cardH), radius, style = Stroke(px(1.5f)))
            drawRoundRect(
                Brand.Gradient,
                Offset(px(10f), y + px(10f)),
                Size(px(32f), px(32f)),
                CornerRadius(px(10f)),
                alpha = alpha,
            )
            drawRoundRect(line.copy(alpha = alpha), Offset(px(54f), y + px(13f)), Size(px(70f), px(8f)), CornerRadius(px(4f)))
            drawRoundRect(line.copy(alpha = alpha), Offset(px(54f), y + px(29f)), Size(px(104f), px(10f)), CornerRadius(px(5f)))
            drawArc(
                Brand.Mint.copy(alpha = alpha),
                -90f,
                120f + index * 60f,
                useCenter = false,
                topLeft = Offset(cardW - px(42f), y + px(12f)),
                size = Size(px(28f), px(28f)),
                style = Stroke(px(3f), cap = StrokeCap.Round),
            )
        }
    }
}

/** First run of the list: an illustration, one sentence and the two ways to start. */
@Composable
fun EmptyCodes(
    onAdd: () -> Unit,
    onImport: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = Space.Xxl, vertical = Space.Xl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Space.Lg, Alignment.CenterVertically),
    ) {
        EmptyIllustration()
        Text(stringResource(R.string.empty_title), style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        Text(
            stringResource(R.string.empty_body),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Button(onClick = onAdd, modifier = Modifier.fillMaxWidth().padding(top = Space.Sm)) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Text(stringResource(R.string.empty_add), modifier = Modifier.padding(start = Space.Sm))
        }
        OutlinedButton(onClick = onImport, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.empty_import)) }
    }
}

/** A search or tag filter that matches nothing. */
@Composable
fun NoResults(modifier: Modifier = Modifier) {
    Column(
        modifier.fillMaxSize().padding(Space.Xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Space.Sm, Alignment.CenterVertically),
    ) {
        Text(stringResource(R.string.no_results_title), style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        Text(
            stringResource(R.string.no_results_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}
