// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support

import com.qtekfun.ultimateotp.core.support.lock.Cancellable
import com.qtekfun.ultimateotp.core.support.lock.InactivityLock
import com.qtekfun.ultimateotp.core.support.lock.LockScheduler
import com.qtekfun.ultimateotp.core.support.lock.LockTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class InactivityLockTest {
    /** A fake clock that also runs the lock's timers when time passes. */
    private class World : LockScheduler {
        var now = 1_000L
        var locks = 0

        private class Timer(
            val at: Long,
            val action: () -> Unit,
            var cancelled: Boolean = false,
        )

        private val timers = mutableListOf<Timer>()

        override fun schedule(
            delayMs: Long,
            action: () -> Unit,
        ): Cancellable {
            val t = Timer(now + delayMs, action)
            timers += t
            return Cancellable { t.cancelled = true }
        }

        fun advance(ms: Long) {
            val end = now + ms
            while (true) {
                val next = timers.filter { !it.cancelled && it.at <= end }.minByOrNull { it.at } ?: break
                now = next.at
                timers.remove(next)
                next.action()
            }
            now = end
        }
    }

    private fun lock(
        timeout: LockTimeout,
        w: World = World(),
    ) = w to InactivityLock({ w.now }, { w.locks++ }, w, timeout)

    @Test
    fun `immediately locks as the app is left, and as the screen turns off`() {
        val (w, l) = lock(LockTimeout.IMMEDIATELY)
        l.onAppBackground()
        assertEquals(1, w.locks)
        l.onAppForeground()
        l.onScreenOff()
        assertEquals(2, w.locks) // a new absence locks again
    }

    @Test
    fun `a timeout locks in the background even if the user never returns`() {
        val (w, l) = lock(LockTimeout.SECONDS_30)
        l.onAppBackground()
        w.advance(29_999)
        assertEquals(0, w.locks)
        w.advance(1)
        assertEquals(1, w.locks)
        l.onAppForeground()
        assertEquals(1, w.locks) // one absence locks once
    }

    @Test
    fun `returning before the timeout cancels it`() {
        val (w, l) = lock(LockTimeout.MINUTE_1)
        l.onAppBackground()
        w.advance(59_000)
        l.onAppForeground()
        w.advance(120_000)
        assertEquals(0, w.locks)
        assertFalse(l.expired())
    }

    @Test
    fun `returning after the timeout locks at once when no timer ran`() {
        val w = World()
        val l = InactivityLock({ w.now }, { w.locks++ }, timeout = LockTimeout.SECONDS_30) // no scheduler: the process was frozen
        l.onAppBackground()
        w.now += 31_000
        assertTrue(l.expired())
        l.onAppForeground()
        assertEquals(1, w.locks)
    }

    @Test
    fun `screen off starts the clock while the app stays foreground, screen on resumes`() {
        val (w, l) = lock(LockTimeout.MINUTES_5)
        l.onScreenOff()
        w.advance(4 * 60_000)
        l.onScreenOn()
        assertEquals(0, w.locks)
        l.onScreenOff()
        w.advance(5 * 60_000)
        assertEquals(1, w.locks)
    }

    @Test
    fun `the earlier of leaving and screen off counts, and both must end`() {
        val (w, l) = lock(LockTimeout.SECONDS_30)
        l.onAppBackground()
        w.advance(20_000)
        l.onScreenOff() // later: does not restart the clock
        w.advance(10_000)
        assertEquals(1, w.locks)
        val (w2, l2) = lock(LockTimeout.SECONDS_30)
        l2.onAppBackground()
        l2.onScreenOff()
        w2.advance(10_000)
        l2.onScreenOn() // app still in the background: not active, clock keeps running
        w2.advance(20_000)
        assertEquals(1, w2.locks)
    }

    @Test
    fun `never does not lock`() {
        val (w, l) = lock(LockTimeout.NEVER)
        l.onAppBackground()
        l.onScreenOff()
        w.advance(7 * 24 * 3_600_000L)
        l.onScreenOn()
        l.onAppForeground()
        assertEquals(0, w.locks)
    }

    @Test
    fun `changing the setting applies to a running absence`() {
        val (w, l) = lock(LockTimeout.MINUTES_5)
        l.onAppBackground()
        w.advance(40_000)
        l.timeout = LockTimeout.SECONDS_30
        assertEquals(1, w.locks)
        val (w2, l2) = lock(LockTimeout.SECONDS_30)
        l2.onAppBackground()
        w2.advance(10_000)
        l2.timeout = LockTimeout.NEVER
        w2.advance(10 * 60_000)
        assertEquals(0, w2.locks)
    }

    @Test
    fun `stored values map to timeouts and unknown ones to the default`() {
        assertEquals(LockTimeout.IMMEDIATELY, LockTimeout.fromStored(0))
        assertEquals(LockTimeout.NEVER, LockTimeout.fromStored(-1))
        assertEquals(LockTimeout.MINUTES_5, LockTimeout.fromStored(300))
        assertEquals(LockTimeout.DEFAULT, LockTimeout.fromStored(45))
        assertEquals(setOf(0, 30, 60, 300, -1), LockTimeout.entries.map { it.stored }.toSet())
    }
}
