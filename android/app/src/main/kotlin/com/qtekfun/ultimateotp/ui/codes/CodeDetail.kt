// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.ui.components.CountdownRing
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.theme.CodeStyles
import com.qtekfun.ultimateotp.ui.theme.ContentMaxWidth
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.ui.theme.status

/** The detail pane of the two-pane layout: one account large, with its actions. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun CodeDetail(
    item: VaultItem,
    now: Long,
    copied: Boolean,
    on: CodesActions,
    modifier: Modifier = Modifier,
) {
    val otp = item.otp
    val view = codeView(item, now)
    Column(
        modifier.verticalScroll(rememberScrollState()).padding(Space.Xl),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            Modifier.widthIn(max = ContentMaxWidth).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(Space.Lg),
        ) {
            IssuerAvatar(otp.issuer, otp.label, iconKey = item.icon, size = 88.dp)
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(otp.issuer.ifEmpty { otp.label }, style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
                if (otp.issuer.isNotEmpty()) {
                    Text(otp.label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Text(
                formatCode(view.code),
                style = CodeStyles.Hero,
                color = if (copied) MaterialTheme.status.success else MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
            )
            if (otp.type != OtpType.HOTP) {
                CountdownRing(view.remainingMillis, otp.period, size = 64.dp)
                Text(
                    if (view.next != null) stringResource(R.string.next_preview, formatCode(view.next)) else "",
                    style = CodeStyles.Small,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
                Button(onClick = { on.onCopy(item, view.code) }) {
                    Icon(if (copied) Icons.Filled.Check else Icons.Filled.ContentCopy, contentDescription = null)
                    Text(
                        stringResource(if (copied) R.string.copied else R.string.copy_code),
                        modifier = Modifier.padding(start = Space.Sm),
                    )
                }
                if (otp.type == OtpType.HOTP) {
                    OutlinedButton(onClick = { on.onNext(item) }) {
                        Icon(Icons.Filled.Refresh, contentDescription = null)
                        Text(stringResource(R.string.next_code), modifier = Modifier.padding(start = Space.Sm))
                    }
                }
            }
            if (otp.tags.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.Sm), verticalArrangement = Arrangement.spacedBy(Space.Sm)) {
                    otp.tags.forEach { AssistChip(onClick = { on.onTag(it) }, label = { Text(it) }) }
                }
            }
            if (item.notes.isNotBlank()) {
                Text(item.notes, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.Sm), verticalArrangement = Arrangement.spacedBy(Space.Sm)) {
                OutlinedButton(onClick = { on.onEdit(item.id) }) {
                    Icon(Icons.Filled.Edit, contentDescription = null)
                    Text(stringResource(R.string.menu_edit), modifier = Modifier.padding(start = Space.Sm))
                }
                OutlinedButton(onClick = { on.onTogglePin(item) }) {
                    Icon(Icons.Filled.PushPin, contentDescription = null)
                    Text(
                        stringResource(if (item.favorite) R.string.menu_unpin else R.string.menu_pin),
                        modifier = Modifier.padding(start = Space.Sm),
                    )
                }
                OutlinedButton(onClick = { on.onDeleteDialog(item.id) }) {
                    Icon(Icons.Filled.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                    Text(
                        stringResource(R.string.delete),
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(start = Space.Sm),
                    )
                }
            }
        }
    }
}
