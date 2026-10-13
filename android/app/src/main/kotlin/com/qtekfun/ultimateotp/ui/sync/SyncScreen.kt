// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import android.graphics.Bitmap
import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.EnrollLink
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.ui.add.QrScanner
import com.qtekfun.ultimateotp.ui.settings.PasswordDialog

private const val QR_PIXELS = 512
private const val BLACK = 0xFF000000.toInt()
private const val WHITE = 0xFFFFFFFF.toInt()
private const val MAX_LABEL = 64
private const val WORDS_PER_LINE = 3

/** A QR code drawn with ZXing core. */
@Composable
fun QrImage(
    text: String,
    modifier: Modifier = Modifier,
) {
    val bitmap =
        remember(text) {
            val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, QR_PIXELS, QR_PIXELS)
            val pixels = IntArray(QR_PIXELS * QR_PIXELS) { i -> if (matrix[i % QR_PIXELS, i / QR_PIXELS]) BLACK else WHITE }
            Bitmap.createBitmap(pixels, QR_PIXELS, QR_PIXELS, Bitmap.Config.ARGB_8888).asImageBitmap()
        }
    Image(bitmap, contentDescription = null, modifier = modifier)
}

/** The device label sent to the server (plain text there, decision 9): the phone model. */
fun deviceLabel(): String =
    Build.MODEL
        .orEmpty()
        .ifBlank { "Android" }
        .take(MAX_LABEL)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(
    initialLink: String,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    model: SyncViewModel = hiltViewModel(),
) {
    val status by model.status.collectAsState()
    val step by model.step.collectAsState()
    val label = remember { deviceLabel() }
    var enrollLink by remember { mutableStateOf<EnrollLink?>(null) }
    LaunchedEffect(initialLink) { if (initialLink.isNotBlank()) model.handleLink(initialLink, label) { enrollLink = it } }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sync_title)) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                    ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back)) }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StepView(step, model)
            if (step is SyncStep.Idle || step is SyncStep.Done || step is SyncStep.Failed) {
                if (status.account == null) {
                    NoAccount(model, label, enrollLink, onLogin) { enrollLink = it }
                } else {
                    WithAccount(model, status.last, status.offline)
                }
            }
        }
    }
}

@Composable
private fun StepView(
    step: SyncStep,
    model: SyncViewModel,
) {
    when (step) {
        SyncStep.Idle -> {}

        is SyncStep.Busy -> {
            Text(
                stringResource(
                    if (step.what ==
                        SyncStep.Busy.Kind.DERIVING_KEY
                    ) {
                        R.string.deriving_hint
                    } else {
                        R.string.working
                    },
                ),
            )
        }

        is SyncStep.RecoveryWords -> {
            RecoveryWordsCard(step.words, model::reset)
        }

        is SyncStep.PairQr -> {
            Card {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.pair_scan_this))
                    QrImage(step.link.format(), Modifier.fillMaxWidth().aspectRatio(1f))
                    TextButton(onClick = model::reset) { Text(stringResource(R.string.cancel)) }
                }
            }
        }

        is SyncStep.ConfirmPairing -> {
            Card {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.pair_compare, step.device.label))
                    Text(step.words.joinToString(" "), style = MaterialTheme.typography.headlineSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { model.approve(step) }) { Text(stringResource(R.string.pair_match)) }
                        OutlinedButton(onClick = { model.decline(step) }) { Text(stringResource(R.string.pair_no_match)) }
                    }
                }
            }
        }

        is SyncStep.JoinWaiting -> {
            Card {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.pair_waiting))
                    Text(step.words.joinToString(" "), style = MaterialTheme.typography.headlineSmall)
                }
            }
        }

        is SyncStep.Failed -> {
            Text(stringResource(failureText(step.reason)), color = MaterialTheme.colorScheme.error)
        }

        is SyncStep.Done -> {
            Text(stringResource(doneText(step.what)))
        }
    }
}

/** The recovery key, shown once (decision 10). */
@Composable
private fun RecoveryWordsCard(
    words: List<String>,
    onSaved: () -> Unit,
) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.recovery_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.recovery_body))
            Text(
                words.chunked(WORDS_PER_LINE).withIndex().joinToString("\n") { (i, line) ->
                    line.withIndex().joinToString("  ") { (j, w) -> "${i * WORDS_PER_LINE + j + 1}. $w" }
                },
                fontFamily = FontFamily.Monospace,
            )
            Button(onClick = onSaved) { Text(stringResource(R.string.recovery_saved)) }
        }
    }
}

private fun failureText(reason: SyncStep.Reason): Int =
    when (reason) {
        SyncStep.Reason.NETWORK -> R.string.fail_network
        SyncStep.Reason.WRONG_SECRET -> R.string.fail_secret
        SyncStep.Reason.LAN_ONLY -> R.string.fail_lan
        SyncStep.Reason.REJECTED_STATE -> R.string.fail_rejected
        SyncStep.Reason.REFUSED -> R.string.fail_refused
        SyncStep.Reason.SERVER -> R.string.fail_server
        SyncStep.Reason.LOGIN_UNAVAILABLE -> R.string.login_unavailable
    }

private fun doneText(kind: SyncStep.DoneKind): Int =
    when (kind) {
        SyncStep.DoneKind.ENROLLED -> R.string.done_enrolled
        SyncStep.DoneKind.PAIRED -> R.string.done_paired
        SyncStep.DoneKind.PAIRING_DECLINED -> R.string.done_declined
        SyncStep.DoneKind.ROTATED -> R.string.done_rotated
        SyncStep.DoneKind.UPLOADED -> R.string.done_uploaded
    }

private enum class Ask { NEW_ACCOUNT, PASSWORD, RECOVERY }

/** No account yet: sign in (email), join from another device (QR), or use an enrollment token. */
@Composable
private fun NoAccount(
    model: SyncViewModel,
    label: String,
    link: EnrollLink?,
    onLogin: () -> Unit,
    onEnrollLink: (EnrollLink) -> Unit,
) {
    val settings by model.settings.collectAsState()
    var scanning by remember { mutableStateOf(false) }
    var server by remember(settings.serverUrl, link) { mutableStateOf(link?.server ?: settings.serverUrl) }
    var lan by remember(settings.enrollmentUrl) { mutableStateOf(settings.enrollmentUrl) }
    var remote by remember(settings.allowRemoteEnrollment) { mutableStateOf(settings.allowRemoteEnrollment) }
    var token by remember(link) { mutableStateOf(link?.token.orEmpty()) }
    var ask by remember { mutableStateOf<Ask?>(null) }

    Text(stringResource(R.string.sync_intro))
    Button(onClick = onLogin, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.login_title)) }
    OutlinedButton(onClick = { scanning = !scanning }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pair_join)) }
    if (scanning) {
        QrScanner(
            onResult = {
                scanning = false
                model.handleLink(it, label, onEnrollLink)
            },
            modifier = Modifier.fillMaxWidth().aspectRatio(1f),
        )
    }
    HorizontalDivider()
    Text(stringResource(R.string.token_section), style = MaterialTheme.typography.titleMedium)
    OutlinedTextField(server, { server = it }, label = { Text(stringResource(R.string.server_url)) }, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(lan, { lan = it }, label = { Text(stringResource(R.string.lan_url)) }, modifier = Modifier.fillMaxWidth())
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(remote, { remote = it })
        Text(stringResource(R.string.allow_remote_enrollment))
    }
    OutlinedTextField(
        token,
        { token = it },
        label = { Text(stringResource(R.string.enrollment_token)) },
        modifier = Modifier.fillMaxWidth(),
    )
    val ready = server.isNotBlank() && token.isNotBlank()
    val choose = { next: Ask ->
        model.saveServer(server, lan, remote)
        ask = next
    }
    Button(enabled = ready, onClick = { choose(Ask.NEW_ACCOUNT) }, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.create_account))
    }
    OutlinedButton(enabled = ready, onClick = { choose(Ask.PASSWORD) }, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.enroll_password))
    }
    OutlinedButton(enabled = ready, onClick = { choose(Ask.RECOVERY) }, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.enroll_recovery))
    }
    when (ask) {
        Ask.NEW_ACCOUNT -> {
            PasswordDialog(stringResource(R.string.new_password_title), confirm = true, onDismiss = { ask = null }) {
                ask = null
                model.bootstrap(server, token, it, label)
            }
        }

        Ask.PASSWORD -> {
            PasswordDialog(stringResource(R.string.password), confirm = false, onDismiss = { ask = null }) {
                ask = null
                model.enrollWithPassword(server, token, it, label)
            }
        }

        Ask.RECOVERY -> {
            WordsDialog(onDismiss = { ask = null }) {
                ask = null
                model.enrollWithRecoveryKey(server, token, it, label)
            }
        }

        null -> {}
    }
}

@Composable
private fun WordsDialog(
    onDismiss: () -> Unit,
    onWords: (String) -> Unit,
) {
    var words by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.enroll_recovery)) },
        text = { OutlinedTextField(words, { words = it }, label = { Text(stringResource(R.string.recovery_words)) }, minLines = 4) },
        confirmButton = { TextButton(enabled = words.isNotBlank(), onClick = { onWords(words) }) { Text(stringResource(R.string.ok)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** Account set up: status, add a device, active sessions (decision 9), rotation, re-seed (decision 12). */
@Composable
private fun WithAccount(
    model: SyncViewModel,
    last: SyncResult?,
    offline: Boolean,
) {
    val status by model.status.collectAsState()
    val account = status.account ?: return
    var rotate by remember { mutableStateOf(false) }
    var upload by remember { mutableStateOf(false) }

    Text(stringResource(R.string.account_status, account.serverUrl, account.acceptedVersion))
    when {
        offline -> {
            Text(stringResource(R.string.status_offline))
        }

        last is SyncResult.Rejected -> {
            Text(stringResource(R.string.status_rejected), color = MaterialTheme.colorScheme.error)
        }

        last == SyncResult.Revoked -> {
            Text(stringResource(R.string.status_revoked), color = MaterialTheme.colorScheme.error)
        }

        else -> {}
    }
    Button(onClick = model::syncNow, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.sync_now)) }
    Button(onClick = model::startPairing, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pair_add)) }
    if (account.rotationRequired) {
        Text(stringResource(R.string.rotation_required), color = MaterialTheme.colorScheme.error)
        Button(onClick = { rotate = true }) { Text(stringResource(R.string.rotate)) }
    }
    HorizontalDivider()
    Sessions(model, account.devicesRevision)
    HorizontalDivider()
    OutlinedButton(onClick = { upload = true }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.upload_local)) }
    if (rotate) {
        PasswordDialog(stringResource(R.string.rotate), confirm = false, onDismiss = { rotate = false }) {
            rotate = false
            model.rotate(it, null)
        }
    }
    if (upload) {
        AlertDialog(
            onDismissRequest = { upload = false },
            title = { Text(stringResource(R.string.upload_local)) },
            text = { Text(stringResource(R.string.upload_local_body)) },
            confirmButton = {
                TextButton(onClick = {
                    upload = false
                    model.uploadLocalCopy()
                }) { Text(stringResource(R.string.upload_local)) }
            },
            dismissButton = { TextButton(onClick = { upload = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun Sessions(
    model: SyncViewModel,
    devicesRevision: Long,
) {
    val devices by model.devices.collectAsState()
    LaunchedEffect(devicesRevision) { model.loadDevices() }
    Text(stringResource(R.string.sessions_title), style = MaterialTheme.typography.titleMedium)
    devices.forEach { d ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                Text(if (d.isThisDevice) stringResource(R.string.this_device, d.label) else d.label)
                when {
                    d.revoked -> Text(stringResource(R.string.device_revoked))
                    !d.trusted -> Text(stringResource(R.string.device_untrusted), color = MaterialTheme.colorScheme.error)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (!d.trusted && !d.revoked) TextButton(onClick = { model.trust(d.deviceId) }) { Text(stringResource(R.string.trust)) }
                    if (!d.isThisDevice &&
                        !d.revoked
                    ) {
                        TextButton(onClick = { model.revoke(d.deviceId) }) { Text(stringResource(R.string.revoke)) }
                    }
                }
            }
        }
    }
}
