// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import android.app.Application
import android.content.ClipboardManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class AppSettingsAndClipboardTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @After
    fun tearDown() = scope.cancel()

    @Test
    fun `settings keep what is updated`() =
        runBlocking {
            val settings = AppSettings(context)
            settings.update {
                it.copy(lockTimeoutSeconds = 300, clipboardClearSeconds = 10, serverUrl = "https://a", allowRemoteEnrollment = true)
            }
            val now = settings.current()
            assertEquals(300, now.lockTimeoutSeconds)
            assertEquals(10, now.clipboardClearSeconds)
            assertEquals("https://a", now.serverUrl)
            assertTrue(now.allowRemoteEnrollment)
            assertEquals(Settings().enrollmentUrl, now.enrollmentUrl)
        }

    @Test
    fun `a copied code is marked sensitive and lands on the clipboard`() {
        val clipboard = SecureClipboard(context, scope, AppSettings(context))
        clipboard.copy("123456")
        val manager = context.getSystemService(ClipboardManager::class.java)
        val clip = manager.primaryClip
        assertNotNull(clip)
        assertEquals("123456", clip!!.getItemAt(0).text.toString())
        // A second copy replaces the first and restarts the clearing timer.
        clipboard.copy("654321")
        assertEquals(
            "654321",
            manager.primaryClip!!
                .getItemAt(0)
                .text
                .toString(),
        )
    }
}
