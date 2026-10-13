// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.support.lock.Cancellable
import com.qtekfun.ultimateotp.core.support.lock.InactivityLock
import com.qtekfun.ultimateotp.core.support.lock.LockTimeout
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.di.AppScope
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Locks the vault (wipes keys from memory) by the inactivity policy of
 * [InactivityLock]: when the app has been in the background, or the screen off, for the time set
 * in the settings (at once, 30 s, 1 min, 5 min, never). The policy itself is in :core:support.
 */
@Singleton
class AutoLock
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val vault: VaultRepository,
        private val settings: AppSettings,
        private val diagnostics: DiagnosticsLog,
        @AppScope private val scope: CoroutineScope,
    ) : DefaultLifecycleObserver {
        private val policy =
            InactivityLock(
                now = SystemClock::elapsedRealtime,
                lockNow = {
                    vault.lock()
                    diagnostics.event("lock", "vault locked by inactivity")
                },
                scheduler = { delayMs, action ->
                    val job =
                        scope.launch {
                            delay(delayMs)
                            action()
                        }
                    Cancellable { job.cancel() }
                },
            )

        fun start() {
            ProcessLifecycleOwner.get().lifecycle.addObserver(this)
            val screen =
                object : BroadcastReceiver() {
                    override fun onReceive(
                        context: Context,
                        intent: Intent,
                    ) {
                        if (intent.action == Intent.ACTION_SCREEN_OFF) policy.onScreenOff() else policy.onScreenOn()
                    }
                }
            context.registerReceiver(
                screen,
                IntentFilter().apply {
                    addAction(Intent.ACTION_SCREEN_OFF)
                    addAction(Intent.ACTION_SCREEN_ON)
                },
            )
            scope.launch { settings.settings.map { LockTimeout.fromStored(it.lockTimeoutSeconds) }.collect { policy.timeout = it } }
        }

        override fun onStop(owner: LifecycleOwner) = policy.onAppBackground()

        override fun onStart(owner: LifecycleOwner) = policy.onAppForeground()
    }
