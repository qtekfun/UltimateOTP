// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.auth

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.res.stringResource
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.Authenticate

/**
 * The root-level hook of [AuthGate]: shows the authentication prompt the gate asks for, hands
 * the result back, and shows the gate's notices. Emitted once, from the app root, so no screen
 * has to know about the Keystore.
 */
@Composable
fun AuthHost(
    gate: AuthGate,
    authenticate: Authenticate,
) {
    val prompt by gate.prompt.collectAsState()
    val notice by gate.notice.collectAsState()
    LaunchedEffect(prompt) {
        val p = prompt ?: return@LaunchedEffect
        authenticate({ p.succeed() }, { message -> p.fail(message) })
    }
    notice?.let { n ->
        AlertDialog(
            onDismissRequest = gate::noticeShown,
            confirmButton = { TextButton(onClick = gate::noticeShown) { Text(stringResource(R.string.auth_notice_ok)) } },
            text = {
                Text(
                    stringResource(
                        when (n) {
                            Notice.Cancelled -> R.string.auth_cancelled
                            Notice.KeyLost -> R.string.auth_key_lost
                            is Notice.Failed -> R.string.auth_failed
                        },
                    ),
                )
            },
        )
    }
}
