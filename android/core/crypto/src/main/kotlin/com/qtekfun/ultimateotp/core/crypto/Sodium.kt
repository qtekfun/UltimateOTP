// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.util.LibsodiumRandom
import java.util.concurrent.CountDownLatch

/** Loads libsodium once (`sodium_init`); every entry point of this module calls [init]. */
object Sodium {
    @Volatile
    private var ready = false

    fun init() {
        if (ready) return
        synchronized(this) {
            if (!ready) {
                val latch = CountDownLatch(1)
                LibsodiumInitializer.initializeWithCallback { latch.countDown() }
                latch.await()
                ready = true
            }
        }
    }

    /** `randombytes_buf`. */
    fun random(size: Int): ByteArray {
        init()
        return LibsodiumRandom.buf(size).asByteArray()
    }
}

/** Overwrites key material once it is no longer needed (best effort on the JVM). */
fun ByteArray.wipe() = fill(0)
