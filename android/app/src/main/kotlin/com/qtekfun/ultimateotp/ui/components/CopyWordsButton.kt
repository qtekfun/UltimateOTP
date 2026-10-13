// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.ui.components

import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.util.SecureClipboard
import dagger.hilt.android.lifecycle.HiltViewModel
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
    val model: WordsClipboardViewModel = hiltViewModel()
    var copied by rememberSaveable { mutableStateOf(false) }
    OutlinedButton(
        onClick = {
            model.copy(words.joinToString(" "))
            copied = true
        },
    ) {
        Text(stringResource(if (copied) R.string.words_copied else R.string.copy_words))
    }
}
