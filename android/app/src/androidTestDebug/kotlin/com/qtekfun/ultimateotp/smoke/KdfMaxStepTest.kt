// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Process
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.qtekfun.ultimateotp.core.crypto.KdfParams
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Argon2id on the real native library for this ABI, at the largest step the app will ever pick
 * (4 passes, 1 GiB), checked against a key PyNaCl produced. The JVM tests run the host's
 * libsodium; this runs the Android `.so` and JNA's loader for the emulator's ABI. On the debug
 * build (`-Puotp.testBuildType=debug`), because it names classes that R8 renames in `smoke`; the
 * minified build derives the same key through the sign-up journey.
 *
 * It also records what this device would choose: `availMem`, the first rung that fits, the ABI.
 * A 32-bit ABI (`x86` image in CI, `armeabi-v7a` on a phone) is where `size_t` is 4 bytes.
 */
@RunWith(AndroidJUnit4::class)
class KdfMaxStepTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun theMaximumStepDerivesAKeyAnotherImplementationReproduces() {
        val (ops, mem) = PasswordKdf.SENSITIVE_LADDER.first()
        assertEquals(1L shl 30, mem)
        val params = KdfParams(ops, mem, ByteArray(KdfParams.SALT_BYTES) { it.toByte() })
        val key = PasswordKdf.derive(PASSWORD, params)
        assertEquals(PYNACL_KEY, key.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun theStepThisDeviceChoosesIsRunnableHere() {
        val info = ActivityManager.MemoryInfo()
        context.getSystemService(ActivityManager::class.java).getMemoryInfo(info)
        val ladder = PasswordKdf.ladderFor(info.availMem)
        Log.i(
            TAG,
            "abis=${Build.SUPPORTED_ABIS.joinToString()} is64Bit=${Process.is64Bit()} availMem=${info.availMem} " +
                "totalMem=${info.totalMem} lowMemory=${info.lowMemory} ladder=$ladder",
        )
        assertTrue(ladder.isNotEmpty())

        val (params, key) = PasswordKdf.deriveNew(PASSWORD, listOf(ladder.first()))
        assertEquals(ladder.first().second, params.memLimit)
        // Reading it back with the stored parameters is the other device's path.
        assertEquals(key.toList(), PasswordKdf.derive(PASSWORD, params).toList())
    }

    private companion object {
        const val TAG = "UotpKdf"
        const val PASSWORD = "correct horse battery staple pässwörd"
        const val PYNACL_KEY = "51538bb63f2d6ea7cd883f4bbd4ddd98d62e7b76e93471b46030b42e85d0cbd3"
    }
}
