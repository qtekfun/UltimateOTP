// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R

/** The app's mark (a countdown ring with a hand) on a dark rounded tile, as on the launcher icon. */
@Composable
fun UotpLogo(
    modifier: Modifier = Modifier,
    size: Dp = 72.dp,
) {
    Box(
        modifier.size(size).clip(RoundedCornerShape(size * 0.27f)).background(Color(0xFF131A16)),
        contentAlignment = Alignment.Center,
    ) {
        Image(painterResource(R.drawable.ic_logo), contentDescription = null, modifier = Modifier.size(size * 0.62f))
    }
}
