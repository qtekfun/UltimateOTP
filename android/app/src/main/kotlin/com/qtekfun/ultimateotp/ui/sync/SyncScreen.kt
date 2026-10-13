// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

@Composable
fun SyncScreen(
    initialLink: String,
    onBack: () -> Unit,
) {
    Button(onClick = onBack) { Text(initialLink) }
}
