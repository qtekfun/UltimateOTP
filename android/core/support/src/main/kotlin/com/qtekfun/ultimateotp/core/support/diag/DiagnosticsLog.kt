// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support.diag

import java.io.File
import java.time.Instant

/** Facts that let a stack trace of a minified build be read: filled in by the app at start-up. */
data class BuildDescription(
    val appVersion: String,
    val versionCode: Int,
    val buildType: String,
    /** R8's map id (`r8-map-id-…`), or null for an unminified build. */
    val mapId: String?,
    val androidSdk: Int,
) {
    fun header(): String =
        buildString {
            appendLine("UltimateOTP diagnostics")
            appendLine("app: $appVersion ($versionCode) $buildType")
            appendLine("r8 map id: ${mapId ?: "none (not minified)"}")
            appendLine("android sdk: $androidSdk")
        }
}

/**
 * A local, bounded diagnostics log. Nothing leaves the device unless the user exports it.
 *
 * - [event] keeps the last [ringSize] non-sensitive events in memory only;
 * - [error] and [recordCrash] append to a private file together with the ring's tail, so a crash
 *   report shows what led to it;
 * - the file is capped at [maxFileBytes] and rotated into at most [keepFiles] files;
 * - every text passes through [Redactor] before it is stored.
 */
class DiagnosticsLog(
    private val dir: File,
    private val build: BuildDescription,
    private val clock: () -> Long = System::currentTimeMillis,
    private val maxFileBytes: Int = DEFAULT_MAX_BYTES,
    private val keepFiles: Int = 2,
    private val ringSize: Int = RING,
) {
    private val ring = ArrayDeque<String>()
    private val lock = Any()

    private val current get() = File(dir, "errors.log")

    private fun rotated(n: Int) = File(dir, "errors.$n.log")

    /** A harmless fact ("sync ok", "locked"). Memory only; pass counts and kinds, not content. */
    fun event(
        category: String,
        message: String,
    ) {
        val line = format("EVENT", category, message)
        synchronized(lock) {
            ring.addLast(line)
            while (ring.size > ringSize) ring.removeFirst()
        }
    }

    /** A handled problem: kept in the file with the events before it. */
    fun error(
        category: String,
        message: String,
        error: Throwable? = null,
    ) {
        val text = format("ERROR", category, message) + (error?.let { "\n" + Redactor.redactTrace(it) } ?: "")
        write(text)
    }

    /** What the uncaught-exception handler calls. */
    fun recordCrash(
        threadName: String,
        error: Throwable,
    ) {
        write(format("CRASH", "thread $threadName", "uncaught exception") + "\n" + Redactor.redactTrace(error))
    }

    private fun format(
        level: String,
        category: String,
        message: String,
    ): String = "${Instant.ofEpochMilli(clock())} [$level] ${Redactor.redact(category)}: ${Redactor.redact(message)}"

    private fun write(entry: String) {
        synchronized(lock) {
            try {
                dir.mkdirs()
                val tail = ring.takeLast(TAIL_EVENTS).joinToString("\n", prefix = "  recent events:\n") { "    $it" }
                val record = entry + "\n" + (if (ring.isEmpty()) "" else tail + "\n")
                val bytes = record.toByteArray(Charsets.UTF_8).let { if (it.size > maxFileBytes / 2) it.copyOf(maxFileBytes / 2) else it }
                if (current.length() + bytes.size > maxFileBytes) rotate()
                current.appendBytes(bytes)
            } catch (_: java.io.IOException) {
                // Diagnostics must never take the app down.
            }
        }
    }

    private fun rotate() {
        for (n in keepFiles - 1 downTo 1) {
            val from = if (n == 1) current else rotated(n - 1)
            if (from.exists()) {
                rotated(n).delete()
                from.renameTo(rotated(n))
            }
        }
        if (keepFiles <= 1) current.delete()
    }

    /** The text to share or save: the header, then the stored records oldest first. */
    fun export(): String =
        synchronized(lock) {
            val body = allFiles().filter { it.exists() }.joinToString("\n") { it.readText(Charsets.UTF_8) }
            build.header() + "\n" + body.ifBlank { "(no errors recorded)\n" }
        }

    /** Size of everything stored, in bytes. */
    fun sizeBytes(): Long = synchronized(lock) { allFiles().sumOf { if (it.exists()) it.length() else 0L } }

    private fun allFiles(): List<File> = (keepFiles - 1 downTo 1).map(::rotated) + current

    fun clear() {
        synchronized(lock) {
            ring.clear()
            for (n in 1 until keepFiles) rotated(n).delete()
            current.delete()
        }
    }

    /** Records uncaught exceptions here, then lets the previous handler (the system's) run. */
    fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            recordCrash(thread.name, throwable)
            previous?.uncaughtException(thread, throwable)
        }
    }

    companion object {
        const val DEFAULT_MAX_BYTES = 64 * 1024
        private const val RING = 200
        private const val TAIL_EVENTS = 30
    }
}
