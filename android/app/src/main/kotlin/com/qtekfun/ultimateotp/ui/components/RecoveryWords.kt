// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.theme.CodeStyles
import com.qtekfun.ultimateotp.ui.theme.Space

private val THREE_COLUMNS_FROM = 400.dp

/** The recovery words in a bordered grid of two columns (three when wide), numbered. */
@Composable
fun RecoveryWordsGrid(
    words: List<String>,
    modifier: Modifier = Modifier,
) {
    val description = words.withIndex().joinToString(", ") { (i, w) -> "${i + 1}, $w" }
    Surface(
        modifier.fillMaxWidth().semantics { contentDescription = description },
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        BoxWithConstraints(Modifier.padding(Space.Lg)) {
            val columns = if (maxWidth >= THREE_COLUMNS_FROM) 3 else 2
            val rows = words.chunked(columns)
            Column(verticalArrangement = Arrangement.spacedBy(Space.Md)) {
                rows.forEachIndexed { r, row ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(Space.Sm)) {
                        row.forEachIndexed { c, word ->
                            Row(
                                Modifier.weight(1f),
                                horizontalArrangement = Arrangement.spacedBy(Space.Sm),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    "${r * columns + c + 1}",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.widthIn(min = 20.dp),
                                )
                                Text(word, style = CodeStyles.Small, color = MaterialTheme.colorScheme.onSurface, maxLines = 1)
                            }
                        }
                        repeat(columns - row.size) { Row(Modifier.weight(1f)) {} }
                    }
                }
            }
        }
    }
}

/**
 * Copies the recovery words as one line, to paste into a password manager (screenshots are blocked).
 * [onCopy] uses the app's secure clipboard: marked sensitive, so no preview, and cleared after the delay.
 */
@Composable
fun CopyWordsButton(
    words: List<String>,
    onCopy: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var copied by rememberSaveable { mutableStateOf(false) }
    FilledTonalButton(
        onClick = {
            onCopy(words.joinToString(" "))
            copied = true
        },
        modifier = modifier,
    ) {
        Icon(if (copied) Icons.Filled.Check else Icons.Filled.ContentCopy, contentDescription = null)
        Text(stringResource(if (copied) R.string.words_copied else R.string.copy_words), modifier = Modifier.padding(start = Space.Sm))
    }
}
