// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.codes

import androidx.compose.animation.Crossfade
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.otp.OtpGenerator
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.ui.components.CountdownRing
import com.qtekfun.ultimateotp.ui.components.IssuerAvatar
import com.qtekfun.ultimateotp.ui.theme.CodeStyles
import com.qtekfun.ultimateotp.ui.theme.Space
import com.qtekfun.ultimateotp.ui.theme.status

private const val MILLIS = 1_000L
private const val PREVIEW_SECONDS = 5

/** The code of [item] at [now] and when it changes; HOTP never expires on its own. */
data class CodeView(
    val code: String,
    val next: String?,
    val remainingMillis: Long,
    val showNext: Boolean,
)

fun codeView(
    item: VaultItem,
    now: Long,
): CodeView {
    val otp = item.otp
    val code = OtpGenerator.code(otp, now)
    if (otp.type == OtpType.HOTP) return CodeView(code, null, 0, false)
    val remaining = OtpGenerator.millisUntilNextStep(now, otp.period)
    val soon = remaining <= PREVIEW_SECONDS * MILLIS && otp.period > PREVIEW_SECONDS
    return CodeView(code, if (soon) OtpGenerator.code(otp, now + otp.period * MILLIS) else null, remaining, soon)
}

/**
 * One account: its logo, issuer and account name, the code in groups, a countdown ring (or a next
 * button for HOTP) and, in the last seconds, a faded preview of the next code.
 * Tap copies, long press opens the menu.
 */
@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
@Composable
fun CodeCard(
    item: VaultItem,
    now: Long,
    compact: Boolean,
    selected: Boolean,
    copied: Boolean,
    onCopy: (String) -> Unit,
    onMenu: () -> Unit,
    onNext: () -> Unit,
    modifier: Modifier = Modifier,
    hidden: Boolean = false,
    dragHandle: Modifier = Modifier,
) {
    val otp = item.otp
    val view = remember(item, now / MILLIS) { codeView(item, now) }
    val title = otp.issuer.ifEmpty { otp.label }
    val subtitle = if (otp.issuer.isNotEmpty()) otp.label else ""
    val copyLabel = stringResource(R.string.copy_code)
    val menuLabel = stringResource(R.string.more_actions)
    val spokenCode = view.code.toList().joinToString(" ")
    val seconds = ((view.remainingMillis + MILLIS - 1) / MILLIS).toInt()
    val description =
        when {
            hidden -> stringResource(R.string.card_description_hidden, title, subtitle)
            otp.type == OtpType.HOTP -> stringResource(R.string.card_description_hotp, title, subtitle, spokenCode)
            else -> pluralStringResource(R.plurals.card_description, seconds, title, subtitle, spokenCode, seconds)
        }
    val container by animateColorAsState(
        if (selected) MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f) else MaterialTheme.colorScheme.surfaceContainer,
        label = "card colour",
    )
    val shape = MaterialTheme.shapes.large
    Surface(
        modifier =
            modifier
                .clip(shape)
                .combinedClickable(
                    onClickLabel = copyLabel,
                    onLongClickLabel = menuLabel,
                    onClick = { onCopy(view.code) },
                    onLongClick = onMenu,
                ).semantics(mergeDescendants = true) { contentDescription = description },
        shape = shape,
        color = container,
        border = if (selected) BorderStroke(1.5.dp, MaterialTheme.colorScheme.secondary) else null,
    ) {
        val pad = if (compact) Space.Md else Space.Lg
        val avatar = if (compact) 40.dp else 48.dp
        val sub = if (copied) stringResource(R.string.copied) else subtitle
        val codeText = if (hidden) formatCode("0".repeat(view.code.length)).replace('0', '\u2022') else formatCode(view.code)
        val codeColor = if (copied) MaterialTheme.status.success else MaterialTheme.colorScheme.onSurface
        val trailing: @Composable () -> Unit = {
            if (otp.type == OtpType.HOTP) {
                FilledTonalIconButton(onClick = onNext) { Icon(Icons.Filled.Refresh, stringResource(R.string.next_code)) }
            } else {
                Box(Modifier.clearAndSetSemantics {}) {
                    CountdownRing(view.remainingMillis, otp.period, size = if (compact) 36.dp else 44.dp)
                }
            }
        }
        val titleBlock: @Composable (Modifier) -> Unit = { m ->
            Column(m, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.Xs)) {
                    if (item.favorite) {
                        Icon(
                            Icons.Filled.PushPin,
                            contentDescription = stringResource(R.string.pinned),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                    Text(title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                if (sub.isNotEmpty()) {
                    Text(
                        sub,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (copied) MaterialTheme.status.success else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.semantics { if (copied) liveRegion = LiveRegionMode.Polite },
                    )
                }
            }
        }
        val codeRow: @Composable () -> Unit = {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(Space.Md),
                itemVerticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    codeText,
                    style = if (compact) CodeStyles.Medium else CodeStyles.Large,
                    color = codeColor,
                    maxLines = 1,
                    softWrap = false,
                )
                if (!hidden) NextPreview(view)
            }
        }
        if (compact) {
            Column(Modifier.padding(pad), verticalArrangement = Arrangement.spacedBy(Space.Sm)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.Md)) {
                    Leading(copied, title, otp.label, item.icon, avatar, dragHandle)
                    titleBlock(Modifier.weight(1f))
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                    Box(Modifier.weight(1f)) { codeRow() }
                    trailing()
                }
            }
        } else {
            Row(
                Modifier.padding(pad),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Space.Md),
            ) {
                Leading(copied, title, otp.label, item.icon, avatar, dragHandle)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    titleBlock(Modifier)
                    codeRow()
                }
                trailing()
            }
        }
    }
}

@Composable
private fun NextPreview(view: CodeView) {
    val alpha by animateFloatAsState(if (view.showNext) 1f else 0f, tween(300), label = "next preview")
    val next = view.next
    if (next != null || alpha > 0f) {
        Text(
            formatCode(next ?: view.code),
            style = CodeStyles.Small,
            softWrap = false,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            modifier = Modifier.alpha(alpha * 0.7f).clearAndSetSemantics {},
        )
    }
}

/** The logo, or a check in its place for a moment after the code was copied. */
@Composable
private fun Leading(
    copied: Boolean,
    issuer: String,
    label: String,
    iconKey: String?,
    size: Dp,
    dragHandle: Modifier,
) {
    val success = MaterialTheme.status.success
    val onSuccess = MaterialTheme.colorScheme.surface
    Crossfade(copied, label = "avatar") { done ->
        if (done) {
            Box(
                dragHandle.size(size).clip(RoundedCornerShape(size * 0.3f)).background(success),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.Check, contentDescription = null, tint = onSuccess, modifier = Modifier.size(size * 0.55f))
            }
        } else {
            IssuerAvatar(issuer, label, modifier = dragHandle, iconKey = iconKey, size = size)
        }
    }
}
