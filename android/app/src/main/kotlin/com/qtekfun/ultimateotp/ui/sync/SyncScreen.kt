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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.EnrollLink
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.ui.add.QrScanner
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.CalloutKind
import com.qtekfun.ultimateotp.ui.components.CopyWordsButton
import com.qtekfun.ultimateotp.ui.components.FlowScaffold
import com.qtekfun.ultimateotp.ui.components.IconBadge
import com.qtekfun.ultimateotp.ui.components.PasswordField
import com.qtekfun.ultimateotp.ui.components.RecoveryWordsGrid
import com.qtekfun.ultimateotp.ui.components.RowDivider
import com.qtekfun.ultimateotp.ui.components.SettingsGroup
import com.qtekfun.ultimateotp.ui.components.SettingsRow
import com.qtekfun.ultimateotp.ui.components.rememberRetainedText
import com.qtekfun.ultimateotp.ui.components.rememberWordsCopier
import com.qtekfun.ultimateotp.ui.settings.PasswordDialog
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.ui.theme.status

private const val QR_PIXELS = 512
private const val BLACK = 0xFF000000.toInt()
private const val WHITE = 0xFFFFFFFF.toInt()
private const val MAX_LABEL = 64
private const val EMAIL_CODE_LENGTH = 6

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

@Composable
fun SyncScreen(
    initialLink: String,
    onBack: () -> Unit,
    onLogin: () -> Unit,
    onSignup: () -> Unit,
    onSessions: () -> Unit,
    model: SyncViewModel = hiltViewModel(),
) {
    val status by model.status.collectAsState()
    val step by model.step.collectAsState()
    val words = rememberWordsCopier()
    val label = remember { deviceLabel() }
    var enrollLink by remember { mutableStateOf<EnrollLink?>(null) }
    LaunchedEffect(initialLink) { if (initialLink.isNotBlank()) model.handleLink(initialLink, label) { enrollLink = it } }
    FlowScaffold(title = stringResource(R.string.sync_title), onBack = onBack) {
        StepView(step, model, words)
        if (step is SyncStep.Idle || step is SyncStep.Done || step is SyncStep.Failed) {
            if (status.account == null) {
                NoAccount(model, label, enrollLink, onLogin, onSignup) { enrollLink = it }
            } else {
                WithAccount(model, status.last, status.offline, onSessions)
            }
        }
    }
}

@Composable
private fun StepView(
    step: SyncStep,
    model: SyncViewModel,
    onCopyWords: (String) -> Unit,
) {
    when (step) {
        SyncStep.Idle -> {}

        is SyncStep.Busy -> {
            Callout(
                stringResource(if (step.what == SyncStep.Busy.Kind.DERIVING_KEY) R.string.deriving_hint else R.string.working),
                icon = Icons.Filled.Sync,
            )
        }

        is SyncStep.RecoveryWords -> {
            RecoveryWordsCard(step.words, model::reset, onCopyWords)
        }

        is SyncStep.PairQr -> {
            Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
                Column(
                    Modifier.padding(Space.Lg),
                    verticalArrangement = Arrangement.spacedBy(Space.Md),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(stringResource(R.string.pair_scan_this), style = MaterialTheme.typography.titleMedium)
                    QrImage(
                        step.link.format(),
                        Modifier
                            .fillMaxWidth()
                            .widthIn(max = 360.dp)
                            .aspectRatio(1f)
                            .clip(RoundedCornerShape(12.dp)),
                    )
                    TextButton(onClick = model::reset) { Text(stringResource(R.string.cancel)) }
                }
            }
        }

        is SyncStep.ConfirmPairing -> {
            Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
                Column(Modifier.padding(Space.Lg), verticalArrangement = Arrangement.spacedBy(Space.Md)) {
                    Text(stringResource(R.string.pair_compare, step.device.label), style = MaterialTheme.typography.titleMedium)
                    RecoveryWordsGrid(step.words)
                    Row(horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                        Button(onClick = { model.approve(step) }) { Text(stringResource(R.string.pair_match)) }
                        OutlinedButton(onClick = { model.decline(step) }) { Text(stringResource(R.string.pair_no_match)) }
                    }
                }
            }
        }

        is SyncStep.JoinWaiting -> {
            Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
                Column(Modifier.padding(Space.Lg), verticalArrangement = Arrangement.spacedBy(Space.Md)) {
                    Text(stringResource(R.string.pair_waiting), style = MaterialTheme.typography.titleMedium)
                    RecoveryWordsGrid(step.words)
                }
            }
        }

        is SyncStep.Failed -> {
            val text =
                if (step.code != null) stringResource(R.string.fail_server_code, step.code) else stringResource(failureText(step.reason))
            Callout(text, kind = CalloutKind.ERROR)
        }

        is SyncStep.Done -> {
            Callout(stringResource(doneText(step.what)), kind = CalloutKind.SUCCESS)
        }
    }
}

/** The recovery key, shown once (decision 10). */
@Composable
private fun RecoveryWordsCard(
    words: List<String>,
    onSaved: () -> Unit,
    onCopy: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(Space.Md)) {
        Callout(stringResource(R.string.recovery_body), kind = CalloutKind.WARNING, title = stringResource(R.string.recovery_title))
        RecoveryWordsGrid(words)
        CopyWordsButton(words, onCopy)
        Button(onClick = onSaved, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.recovery_saved)) }
    }
}

private fun failureText(reason: SyncStep.Reason): Int =
    when (reason) {
        SyncStep.Reason.NETWORK -> R.string.fail_network
        SyncStep.Reason.WRONG_SECRET -> R.string.fail_secret
        SyncStep.Reason.LAN_ONLY -> R.string.fail_lan
        SyncStep.Reason.INSECURE_URL -> R.string.fail_insecure_url
        SyncStep.Reason.REJECTED_STATE -> R.string.fail_rejected
        SyncStep.Reason.REFUSED -> R.string.fail_refused
        SyncStep.Reason.SERVER -> R.string.fail_server
        SyncStep.Reason.LOGIN_UNAVAILABLE -> R.string.login_unavailable
        SyncStep.Reason.UNEXPECTED -> R.string.problem_unexpected
    }

private fun doneText(kind: SyncStep.DoneKind): Int =
    when (kind) {
        SyncStep.DoneKind.ENROLLED -> R.string.done_enrolled
        SyncStep.DoneKind.PAIRED -> R.string.done_paired
        SyncStep.DoneKind.PAIRING_DECLINED -> R.string.done_declined
        SyncStep.DoneKind.ROTATED -> R.string.done_rotated
        SyncStep.DoneKind.UPLOADED -> R.string.done_uploaded
        SyncStep.DoneKind.PASSWORD_CHANGED -> R.string.done_password
    }

private enum class Ask { NEW_ACCOUNT, PASSWORD, RECOVERY }

/**
 * No account yet: create one or log in (email), join from another device (QR), or, under
 * "Advanced", use an enrollment token from the server's CLI.
 */
@Composable
private fun NoAccount(
    model: SyncViewModel,
    label: String,
    link: EnrollLink?,
    onLogin: () -> Unit,
    onSignup: () -> Unit,
    onEnrollLink: (EnrollLink) -> Unit,
) {
    val settings by model.settings.collectAsState()
    var scanning by remember { mutableStateOf(false) }
    var server by rememberSaveable(settings.serverUrl, link) { mutableStateOf(link?.server ?: settings.serverUrl) }
    var lan by rememberSaveable(settings.enrollmentUrl) { mutableStateOf(settings.enrollmentUrl) }
    var remote by rememberSaveable(settings.allowRemoteEnrollment) { mutableStateOf(settings.allowRemoteEnrollment) }
    var token by rememberRetainedText("sync-token", link?.token.orEmpty())
    var emailCode by rememberSaveable { mutableStateOf("") }
    var ask by rememberSaveable { mutableStateOf<Ask?>(null) }
    var advanced by rememberSaveable(link) { mutableStateOf(link != null) }

    Row(horizontalArrangement = Arrangement.spacedBy(Space.Lg), verticalAlignment = Alignment.CenterVertically) {
        IconBadge(Icons.Filled.CloudSync, size = 56.dp)
        Text(stringResource(R.string.sync_intro), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
    }
    Button(onClick = onSignup, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) { Text(stringResource(R.string.welcome_signup)) }
    FilledTonalButton(onClick = onLogin, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        Text(stringResource(R.string.welcome_login))
    }
    OutlinedButton(onClick = { scanning = !scanning }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
        Icon(Icons.Filled.QrCodeScanner, contentDescription = null)
        Text(stringResource(R.string.pair_join), modifier = Modifier.padding(start = Space.Sm))
    }
    if (scanning) {
        QrScanner(
            onResult = {
                scanning = false
                model.handleLink(it, label, onEnrollLink)
            },
            modifier = Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(24.dp)),
        )
    }
    TextButton(onClick = { advanced = !advanced }) { Text(stringResource(R.string.advanced_token)) }
    if (!advanced) return
    Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
        Column(Modifier.padding(Space.Lg), verticalArrangement = Arrangement.spacedBy(Space.Md)) {
            Text(stringResource(R.string.token_section), style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                server,
                { server = it },
                label = { Text(stringResource(R.string.server_url)) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(lan, { lan = it }, label = { Text(stringResource(R.string.lan_url)) }, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(remote, { remote = it })
                Text(stringResource(R.string.allow_remote_enrollment), style = MaterialTheme.typography.bodyMedium)
            }
            OutlinedTextField(
                token,
                { token = it },
                label = { Text(stringResource(R.string.enrollment_token)) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                emailCode,
                { emailCode = it.filter(Char::isDigit).take(EMAIL_CODE_LENGTH) },
                label = { Text(stringResource(R.string.bootstrap_email_code)) },
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
        }
    }
    when (ask) {
        Ask.NEW_ACCOUNT -> {
            PasswordDialog(stringResource(R.string.new_password_title), confirm = true, onDismiss = { ask = null }) {
                ask = null
                model.bootstrap(server, token, it, label, emailCode)
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
    var words by rememberRetainedText("sync-words")
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
    onSessions: () -> Unit,
) {
    val status by model.status.collectAsState()
    val account = status.account ?: return
    var rotate by remember { mutableStateOf(false) }
    var upload by remember { mutableStateOf(false) }

    val problem = last is SyncResult.Rejected || last == SyncResult.Revoked
    val (icon, text, tint) =
        when {
            offline -> {
                Triple(Icons.Filled.CloudOff, stringResource(R.string.status_offline), MaterialTheme.colorScheme.onSurfaceVariant)
            }

            last is SyncResult.Rejected -> {
                Triple(
                    Icons.Filled.ErrorOutline,
                    stringResource(R.string.status_rejected),
                    MaterialTheme.colorScheme.error,
                )
            }

            last == SyncResult.Revoked -> {
                Triple(
                    Icons.Filled.ErrorOutline,
                    stringResource(R.string.status_revoked),
                    MaterialTheme.colorScheme.error,
                )
            }

            else -> {
                Triple(Icons.Filled.CloudDone, stringResource(R.string.status_synced), MaterialTheme.status.success)
            }
        }
    Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
        Column(Modifier.padding(Space.Lg), verticalArrangement = Arrangement.spacedBy(Space.Md)) {
            Row(horizontalArrangement = Arrangement.spacedBy(Space.Lg), verticalAlignment = Alignment.CenterVertically) {
                IconBadge(icon, tint = tint, size = 48.dp)
                Column {
                    Text(
                        text,
                        style = MaterialTheme.typography.titleMedium,
                        color = if (problem) MaterialTheme.colorScheme.error else Color.Unspecified,
                    )
                    Text(
                        stringResource(R.string.account_status, account.serverUrl, account.acceptedVersion),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            FilledTonalButton(onClick = model::syncNow, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.sync_now)) }
        }
    }
    if (account.rotationRequired) {
        Callout(stringResource(R.string.rotation_required), kind = CalloutKind.WARNING)
        Button(onClick = { rotate = true }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.rotate)) }
    }
    SettingsGroup(stringResource(R.string.section_devices)) {
        SettingsRow(
            Icons.Filled.QrCodeScanner,
            stringResource(R.string.pair_add),
            subtitle = stringResource(R.string.pair_add_body),
            onClick = model::startPairing,
        )
        RowDivider()
        SettingsRow(
            Icons.Filled.Devices,
            stringResource(R.string.sessions_title),
            subtitle = stringResource(R.string.sessions_body),
            onClick = onSessions,
        )
    }
    SettingsGroup(stringResource(R.string.section_account)) {
        ChangePassword(model)
        RowDivider()
        NewRecoveryKey(model)
        RowDivider()
        SettingsRow(
            Icons.Filled.Upload,
            stringResource(
                R.string.upload_local,
            ),
            subtitle = stringResource(R.string.upload_local_hint),
            onClick = {
                upload =
                    true
            },
        )
    }
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

/** Makes and shows a new recovery key after the current password; the old words stop working. */
@Composable
private fun NewRecoveryKey(model: SyncViewModel) {
    var open by rememberSaveable { mutableStateOf(false) }
    SettingsRow(
        Icons.Filled.Key,
        stringResource(R.string.new_recovery_key),
        subtitle = stringResource(R.string.new_recovery_key_hint),
        onClick = { open = true },
    )
    if (open) {
        PasswordDialog(stringResource(R.string.new_recovery_key), confirm = false, onDismiss = { open = false }) {
            open = false
            model.newRecoveryKey(it)
        }
    }
}

/** New master password, proved by the current one or by the 24 recovery words (after recovery). */
@Composable
private fun ChangePassword(model: SyncViewModel) {
    var open by rememberSaveable { mutableStateOf(false) }
    SettingsRow(Icons.Filled.Key, stringResource(R.string.change_password), onClick = { open = true })
    if (!open) return
    var current by rememberRetainedText("change-current")
    var words by rememberRetainedText("change-words")
    var next by rememberRetainedText("change-new")
    var repeat by rememberRetainedText("change-repeat")
    val ok = next.length >= MIN_NEW_PASSWORD && next == repeat && (current.isNotEmpty() || words.isNotBlank())
    AlertDialog(
        onDismissRequest = { open = false },
        title = { Text(stringResource(R.string.change_password)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Space.Sm)) {
                PasswordField(current, { current = it }, stringResource(R.string.current_password))
                OutlinedTextField(words, { words = it }, label = { Text(stringResource(R.string.or_recovery_words)) }, minLines = 2)
                PasswordField(next, { next = it }, stringResource(R.string.new_password))
                PasswordField(repeat, { repeat = it }, stringResource(R.string.password_repeat))
            }
        },
        confirmButton = {
            TextButton(enabled = ok, onClick = {
                open = false
                model.changePassword(next, current, words)
            }) { Text(stringResource(R.string.ok)) }
        },
        dismissButton = { TextButton(onClick = { open = false }) { Text(stringResource(R.string.cancel)) } },
    )
}

private const val MIN_NEW_PASSWORD = 8
