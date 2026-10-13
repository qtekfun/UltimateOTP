// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

/** Facts about this build that make a minified stack trace readable (docs/diagnostics.md). */
object BuildInfo {
    private const val MAP_ID_PREFIX = "r8-map-id-"
    private const val PLAIN_NAME = "com.qtekfun.ultimateotp.util.BuildInfo"

    /**
     * R8 writes its map id into the source-file name of a minified frame (`r8-map-id-<id>`),
     * so one frame of our own is enough. Null for an unminified build; a hint when the classes
     * are renamed but the id is not embedded (match the trace to the build's `mapping.txt`
     * by version code).
     */
    fun mapId(): String? {
        val frames = Throwable("stack probe").stackTrace
        frames
            .firstNotNullOfOrNull {
                it.fileName?.takeIf { f ->
                    f.startsWith(MAP_ID_PREFIX)
                }
            }?.let { return it.removeSuffix(".java").removeSuffix(".kt") }
        return if (BuildInfo::class.java.name == PLAIN_NAME) null else "obfuscated, id not embedded (use this version code's mapping.txt)"
    }
}
