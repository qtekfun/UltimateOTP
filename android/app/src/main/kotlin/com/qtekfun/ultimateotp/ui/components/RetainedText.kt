// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel

/** Text typed into secret fields, held in memory by the screen's view-model store, never in a saved-state Bundle. */
class RetainedFields : ViewModel() {
    val values = mutableStateMapOf<String, String>()
}

/**
 * Text state for a field that holds a secret (a password, a TOTP key, a token, pasted otpauth links).
 * It survives a fold, unfold or rotation (the view-model store outlives the activity) but is not
 * written to saved instance state, so it cannot reach disk, and it is gone with the process or the
 * screen. [key] must be unique within the screen.
 */
@Composable
fun rememberRetainedText(
    key: String,
    initial: String = "",
): MutableState<String> {
    val store = viewModel<RetainedFields>()
    return remember(store, key) {
        object : MutableState<String> {
            override var value: String
                get() = store.values[key] ?: initial
                set(newValue) {
                    store.values[key] = newValue
                }

            override fun component1(): String = value

            override fun component2(): (String) -> Unit = { value = it }
        }
    }
}
