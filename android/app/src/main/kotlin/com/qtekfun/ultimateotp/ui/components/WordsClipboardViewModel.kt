// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.ui.components

import androidx.lifecycle.ViewModel
import com.qtekfun.ultimateotp.util.SecureClipboard
import dagger.hilt.android.lifecycle.HiltViewModel
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
