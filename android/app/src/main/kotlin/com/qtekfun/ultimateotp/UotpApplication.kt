// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp

import android.app.Application
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.util.AutoLock
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

@HiltAndroidApp
class UotpApplication : Application() {
    @Inject lateinit var autoLock: AutoLock

    @Inject lateinit var sync: SyncController

    override fun onCreate() {
        super.onCreate()
        autoLock.start()
        sync.start()
    }
}
