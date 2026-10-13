// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.theme.ContentMaxWidth
import com.qtekfun.ultimateotp.ui.theme.Space

/**
 * The layout of every step-by-step screen (sign-up, log in, enrollment): a top bar, a progress bar
 * with "Step n of m", and a centred column that does not grow wider than a phone-sized form.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FlowScaffold(
    title: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    step: Int = 0,
    steps: Int = 0,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        modifier,
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().imePadding(), horizontalAlignment = Alignment.CenterHorizontally) {
            if (steps > 0) StepProgress(step, steps)
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier
                        .widthIn(max = ContentMaxWidth)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = Space.Gutter, vertical = Space.Lg),
                    verticalArrangement = Arrangement.spacedBy(Space.Lg),
                    content = content,
                )
            }
        }
    }
}

/** A thin progress bar and the step counter, for [step] counted from 1. */
@Composable
fun StepProgress(
    step: Int,
    steps: Int,
) {
    val progress by animateFloatAsState(step.toFloat() / steps, label = "step progress")
    val text = stringResource(R.string.step_of, step, steps)
    Column(Modifier.fillMaxWidth().padding(horizontal = Space.Gutter), verticalArrangement = Arrangement.spacedBy(Space.Xs)) {
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier.fillMaxWidth(),
            trackColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            gapSize = 0.dp,
            drawStopIndicator = {},
        )
        Text(text, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** An icon badge, a headline and a short explanation: the top of a step. */
@Composable
fun StepHeader(
    icon: ImageVector,
    title: String,
    body: String? = null,
) {
    Column(verticalArrangement = Arrangement.spacedBy(Space.Md)) {
        IconBadge(icon, size = 56.dp)
        Text(title, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
        if (body != null) Text(body, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
