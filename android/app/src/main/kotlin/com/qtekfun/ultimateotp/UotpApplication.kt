// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp

import android.app.Application
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.util.AutoLock
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

@HiltAndroidApp
class UotpApplication : Application() {
    @Inject lateinit var autoLock: AutoLock

    @Inject lateinit var sync: SyncController

    @Inject lateinit var diagnostics: DiagnosticsLog

    override fun onCreate() {
        super.onCreate()
        // First, so a crash while the rest starts is recorded too.
        diagnostics.installCrashHandler()
        diagnostics.event("app", "started")
        autoLock.start()
        sync.start()
    }
}
