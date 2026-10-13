// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import com.qtekfun.ultimateotp.di.AppScope
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Copies a code marked as sensitive (no clipboard preview on Android 13+) and clears it after
 * the configured delay if it is still ours.
 */
@Singleton
class SecureClipboard
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        @AppScope private val scope: CoroutineScope,
        private val settings: AppSettings,
    ) {
        private var clearJob: Job? = null

        fun copy(code: String) {
            val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
            val clip = ClipData.newPlainText(LABEL, code)
            clip.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
            clipboard.setPrimaryClip(clip)
            clearJob?.cancel()
            clearJob =
                scope.launch {
                    delay(settings.current().clipboardClearSeconds * MILLIS)
                    launch(Dispatchers.Main) { clearIfOurs(clipboard) }
                }
        }

        private fun clearIfOurs(clipboard: ClipboardManager) {
            // In the background the description may be unreadable (Android 10+); clear anyway then,
            // since a code must not outlive its delay.
            val label = runCatching { clipboard.primaryClipDescription?.label }.getOrNull()
            if (label != null && label != LABEL) return
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }

        private companion object {
            const val LABEL = "UltimateOTP code"
            const val MILLIS = 1000L

            // ClipDescription.EXTRA_IS_SENSITIVE (API 33); the literal works on every version.
            val EXTRA_IS_SENSITIVE: String =
                if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.TIRAMISU
                ) {
                    ClipDescription.EXTRA_IS_SENSITIVE
                } else {
                    "android.content.extra.IS_SENSITIVE"
                }
        }
    }
