// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.ui.components

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.util.SecureClipboard
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.internal.GeneratedComponentManager
import javax.inject.Inject

@HiltViewModel
class WordsClipboardViewModel
    @Inject
    constructor(
        private val clipboard: SecureClipboard,
    ) : ViewModel() {
        fun copy(text: String) = clipboard.copy(text)
    }

/**
 * Copies the recovery words as one line, to paste into a password manager (screenshots are blocked).
 * It uses the app's secure clipboard: marked sensitive, so no preview, and cleared after the delay.
 */
@Composable
fun CopyWordsButton(words: List<String>) {
    // Hilt only exists in a Hilt activity; the JVM UI tests host screens in a plain one, where
    // the words go to the plain clipboard (no automatic clearing).
    val context = LocalContext.current
    val model: WordsClipboardViewModel? = if (context.hostActivity() is GeneratedComponentManager<*>) hiltViewModel() else null
    var copied by rememberSaveable { mutableStateOf(false) }
    OutlinedButton(
        onClick = {
            val text = words.joinToString(" ")
            if (model != null) {
                model.copy(text)
            } else {
                context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("", text))
            }
            copied = true
        },
    ) {
        Text(stringResource(if (copied) R.string.words_copied else R.string.copy_words))
    }
}

private tailrec fun Context.hostActivity(): Activity? =
    when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.hostActivity()
        else -> null
    }
