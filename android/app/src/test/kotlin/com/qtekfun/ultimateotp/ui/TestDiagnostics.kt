// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later
package com.qtekfun.ultimateotp.ui

import com.qtekfun.ultimateotp.core.support.diag.BuildDescription
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import java.nio.file.Files

/** A throw-away diagnostics log for tests that build a [com.qtekfun.ultimateotp.sync.SyncController]. */
internal fun testDiagnostics(): DiagnosticsLog =
    DiagnosticsLog(
        dir = Files.createTempDirectory("uotp-diag").toFile(),
        build = BuildDescription(appVersion = "test", versionCode = 0, buildType = "test", mapId = null, androidSdk = 0),
    )
