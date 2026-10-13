// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.di.AppScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/** Locks the vault (wipes keys from memory) after the app spent the configured time in the background. */
@Singleton
class AutoLock
    @Inject
    constructor(
        private val vault: VaultRepository,
        private val settings: AppSettings,
        @AppScope private val scope: CoroutineScope,
    ) : DefaultLifecycleObserver {
        private var backgroundSince: Long? = null

        fun start() = ProcessLifecycleOwner.get().lifecycle.addObserver(this)

        override fun onStop(owner: LifecycleOwner) {
            backgroundSince = SystemClock.elapsedRealtime()
            scope.launch { if (settings.current().lockTimeoutSeconds == 0) vault.lock() }
        }

        override fun onStart(owner: LifecycleOwner) {
            val since = backgroundSince ?: return
            backgroundSince = null
            scope.launch {
                val elapsed = (SystemClock.elapsedRealtime() - since) / MILLIS
                if (elapsed >= settings.current().lockTimeoutSeconds) vault.lock()
            }
        }

        private companion object {
            const val MILLIS = 1000L
        }
    }
