// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.PhonelinkErase
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.DeviceView
import com.qtekfun.ultimateotp.core.sync.api.SessionInfo
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.IconBadge
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.ui.theme.status

private const val MILLIS = 1000L

@Composable
fun SessionsScreen(
    onBack: () -> Unit,
    model: SyncViewModel = hiltViewModel(),
) {
    val devices by model.devices.collectAsState()
    val sessions by model.sessions.collectAsState()
    val status by model.status.collectAsState()
    val account = status.account
    LaunchedEffect(account?.devicesRevision) { if (account != null) model.loadDevices() }
    SessionsContent(
        hasAccount = account != null,
        devices = devices,
        sessions = sessions,
        onTrust = model::trust,
        onRevoke = model::revoke,
        onBack = onBack,
    )
}

/** The device list: one card per device with its state, last seen, and the trust or revoke action. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SessionsContent(
    hasAccount: Boolean,
    devices: List<DeviceView>,
    sessions: Map<String, SessionInfo>,
    onTrust: (String) -> Unit,
    onRevoke: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirm by remember { mutableStateOf<DeviceView?>(null) }
    FlowScaffold(title = stringResource(R.string.sessions_title), onBack = onBack, modifier = modifier) {
        Text(
            stringResource(R.string.sessions_intro),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (!hasAccount) {
            Callout(stringResource(R.string.sessions_no_account))
        }
        devices.forEach { d ->
            Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
                Column(Modifier.padding(Space.Lg), verticalArrangement = Arrangement.spacedBy(Space.Md)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(Space.Lg), verticalAlignment = Alignment.CenterVertically) {
                        IconBadge(
                            if (d.revoked) Icons.Filled.PhonelinkErase else Icons.Filled.PhoneAndroid,
                            tint = if (d.revoked) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.primary,
                            size = 48.dp,
                        )
                        Column(Modifier.weight(1f)) {
                            Text(d.label, style = MaterialTheme.typography.titleMedium, maxLines = 2)
                            sessions[d.deviceId]?.let { info ->
                                Text(
                                    sessionMeta(info),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                    if (d.isThisDevice || d.revoked || !d.trusted) {
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                            if (d.isThisDevice) {
                                StateChip(
                                    stringResource(R.string.this_device_chip),
                                    Icons.Filled.CheckCircle,
                                    MaterialTheme.status.success,
                                )
                            }
                            if (d.revoked) {
                                StateChip(
                                    stringResource(R.string.device_revoked),
                                    Icons.Filled.PhonelinkErase,
                                    MaterialTheme.colorScheme.error,
                                )
                            } else if (!d.trusted) {
                                StateChip(
                                    stringResource(R.string.device_untrusted_chip),
                                    Icons.Filled.WarningAmber,
                                    MaterialTheme.status.warning,
                                )
                            }
                        }
                    }
                    if (!d.trusted && !d.revoked) {
                        Text(
                            stringResource(R.string.device_untrusted),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.status.warning,
                        )
                    }
                    val canTrust = !d.trusted && !d.revoked
                    val canRevoke = !d.isThisDevice && !d.revoked
                    if (canTrust || canRevoke) {
                        Row(horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                            if (!d.trusted && !d.revoked) {
                                FilledTonalButton(onClick = { onTrust(d.deviceId) }) { Text(stringResource(R.string.trust)) }
                            }
                            if (!d.isThisDevice && !d.revoked) {
                                OutlinedButton(onClick = { confirm = d }) {
                                    Text(stringResource(R.string.revoke), color = MaterialTheme.colorScheme.error)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    confirm?.let { d ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(stringResource(R.string.revoke_title, d.label)) },
            text = { Text(stringResource(R.string.revoke_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    onRevoke(d.deviceId)
                }) { Text(stringResource(R.string.revoke), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun StateChip(
    text: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: androidx.compose.ui.graphics.Color,
) {
    AssistChip(
        onClick = {},
        label = { Text(text) },
        leadingIcon = { Icon(icon, contentDescription = null, tint = tint) },
        colors = AssistChipDefaults.assistChipColors(labelColor = MaterialTheme.colorScheme.onSurface),
    )
}

@Composable
private fun sessionMeta(info: SessionInfo): String {
    val seen =
        info.lastSeenAt?.let {
            DateUtils.getRelativeTimeSpanString(it * MILLIS, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString()
        } ?: stringResource(R.string.unknown_value)
    return stringResource(
        R.string.session_meta,
        info.appVersion ?: stringResource(R.string.unknown_value),
        seen,
        info.lastIp ?: stringResource(R.string.unknown_value),
    )
}
