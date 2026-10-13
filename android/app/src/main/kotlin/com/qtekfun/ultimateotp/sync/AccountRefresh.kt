// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.sync

/** Told when this device joined an account, so live sync starts (implemented by [SyncController]). */
fun interface AccountRefresh {
    suspend fun accountChanged()
}
