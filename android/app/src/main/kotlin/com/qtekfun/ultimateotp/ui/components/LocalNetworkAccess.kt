// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import com.qtekfun.ultimateotp.R

/** The first Android version that blocks connections to the home network without the permission. */
private const val LOCAL_NETWORK_API = 37

/**
 * Asks for `ACCESS_LOCAL_NETWORK` when [active] (a connection to the server just failed) and the
 * permission is missing. Since Android 17 an app targeting API 37 cannot reach an address on the
 * home network without it, and a self-hosted server often is one (a LAN address, or a name that
 * split DNS resolves to one): the connection then just times out. The prompt is skipped on older
 * Android, where the permission does not exist, and after a refusal until the screen is left.
 */
@Composable
fun LocalNetworkAccessPrompt(
    active: Boolean,
    onGranted: () -> Unit = {},
) {
    if (Build.VERSION.SDK_INT < LOCAL_NETWORK_API) return
    val context = LocalContext.current
    var dismissed by rememberSaveable { mutableStateOf(false) }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            dismissed = true
            if (granted) onGranted()
        }
    val missing =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_LOCAL_NETWORK) !=
            PackageManager.PERMISSION_GRANTED
    if (!active || !missing || dismissed) return
    AlertDialog(
        onDismissRequest = { dismissed = true },
        title = { Text(stringResource(R.string.local_network_title)) },
        text = { Text(stringResource(R.string.local_network_body)) },
        confirmButton = {
            TextButton(onClick = { launcher.launch(Manifest.permission.ACCESS_LOCAL_NETWORK) }) {
                Text(stringResource(R.string.local_network_allow))
            }
        },
        dismissButton = { TextButton(onClick = { dismissed = true }) { Text(stringResource(R.string.not_now)) } },
    )
}
