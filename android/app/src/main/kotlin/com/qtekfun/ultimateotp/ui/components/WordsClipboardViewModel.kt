// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.ui.components

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import com.qtekfun.ultimateotp.util.SecureClipboard
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.internal.GeneratedComponentManager
import javax.inject.Inject

/** Gives screens the secure clipboard for the recovery words (marked sensitive, cleared after the delay). */
@HiltViewModel
class WordsClipboardViewModel
    @Inject
    constructor(
        private val clipboard: SecureClipboard,
    ) : ViewModel() {
        fun copy(text: String) = clipboard.copy(text)
    }

/**
 * What the screens that show recovery words copy with: the app's secure clipboard in the Hilt
 * activity; in a plain activity (the JVM UI tests host screens in one, and Hilt only exists in a
 * Hilt activity) the words go to the plain clipboard, with no automatic clearing.
 */
@Composable
fun rememberWordsCopier(): (String) -> Unit {
    val context = LocalContext.current
    val model: WordsClipboardViewModel? = if (context.hostActivity() is GeneratedComponentManager<*>) hiltViewModel() else null
    return remember(model, context) {
        { text ->
            if (model != null) {
                model.copy(text)
            } else {
                context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("", text))
            }
        }
    }
}

private tailrec fun Context.hostActivity(): Activity? =
    when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.hostActivity()
        else -> null
    }
