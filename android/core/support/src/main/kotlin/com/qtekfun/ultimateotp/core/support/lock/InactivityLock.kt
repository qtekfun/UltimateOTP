// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support.lock

/** How long the vault stays unlocked after the app is left or the screen turns off. */
enum class LockTimeout(
    /** The value stored in the settings: seconds, or -1 for [NEVER]. */
    val stored: Int,
) {
    IMMEDIATELY(0),
    SECONDS_30(30),
    MINUTE_1(60),
    MINUTES_5(300),
    NEVER(-1),
    ;

    /** Milliseconds, or null for [NEVER]. */
    val millis: Long? get() = if (this == NEVER) null else stored * 1000L

    companion object {
        val DEFAULT = MINUTE_1

        /** Unknown stored values (an older or newer app wrote them) become the default. */
        fun fromStored(value: Int): LockTimeout = entries.firstOrNull { it.stored == value } ?: DEFAULT
    }
}

/** Runs [action] after [delayMs] unless cancelled. The app backs it with a coroutine delay. */
fun interface LockScheduler {
    fun schedule(
        delayMs: Long,
        action: () -> Unit,
    ): Cancellable
}

fun interface Cancellable {
    fun cancel()
}

/**
 * The inactivity lock policy: the vault locks when the app has been out of the foreground, or
 * the screen has been off, for longer than [timeout]. Both start the same clock (the earlier of
 * the two); coming back (app visible and screen on) before the timeout keeps the vault open.
 *
 * With [LockTimeout.IMMEDIATELY] it locks the moment the app is left or the screen turns off. With
 * a finite timeout it also locks while the app stays in the background, via [scheduler], so keys
 * do not sit in memory until the user returns. Pure logic: time comes from [now] (monotonic
 * milliseconds), so tests drive it with a fake clock.
 */
class InactivityLock(
    private val now: () -> Long,
    private val lockNow: () -> Unit,
    private val scheduler: LockScheduler = LockScheduler { _, _ -> Cancellable { } },
    timeout: LockTimeout = LockTimeout.DEFAULT,
) {
    var timeout: LockTimeout = timeout
        set(value) {
            field = value
            // A changed setting applies to an inactivity that is already running.
            if (inactiveSince != null) evaluate()
        }

    private var appVisible = true
    private var screenOn = true
    private var inactiveSince: Long? = null

    /** The lock already fired for the current absence: one absence locks once. */
    private var fired = false
    private var pending: Cancellable? = null

    /** The app left the foreground (all activities stopped). */
    @Synchronized
    fun onAppBackground() {
        appVisible = false
        becameInactive()
    }

    @Synchronized
    fun onAppForeground() {
        appVisible = true
        maybeActive()
    }

    @Synchronized
    fun onScreenOff() {
        screenOn = false
        becameInactive()
    }

    @Synchronized
    fun onScreenOn() {
        screenOn = true
        maybeActive()
    }

    /** True while the vault must be considered locked-out because the timeout already passed. */
    @Synchronized
    fun expired(): Boolean = inactiveSince?.let { fired || isDue(it) } ?: false

    private fun becameInactive() {
        if (inactiveSince == null) inactiveSince = now()
        evaluate()
    }

    private fun maybeActive() {
        if (!appVisible || !screenOn) return
        // Back in time or too late: the check at return is the same rule as the timer's.
        if (!fired && inactiveSince?.let { isDue(it) } == true) lockNow()
        inactiveSince = null
        fired = false
        pending?.cancel()
        pending = null
    }

    private fun isDue(since: Long): Boolean {
        val limit = timeout.millis ?: return false
        return now() - since >= limit
    }

    private fun evaluate() {
        val since = inactiveSince ?: return
        pending?.cancel()
        pending = null
        val limit = timeout.millis ?: return
        if (isDue(since)) {
            if (!fired) lockNow()
            fired = true
        } else {
            pending = scheduler.schedule(limit - (now() - since)) { onTimer() }
        }
    }

    @Synchronized
    private fun onTimer() {
        pending = null
        evaluate()
    }
}
