// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.support

import com.qtekfun.ultimateotp.core.support.diag.BuildDescription
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.support.diag.Redactor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class DiagnosticsLogTest {
    @TempDir lateinit var dir: File

    private val build = BuildDescription("0.2.0", 4, "release", "r8-map-id-1a2b3c", 36)

    private fun log(
        max: Int = 64 * 1024,
        keep: Int = 2,
    ) = DiagnosticsLog(dir, build, clock = { 1_700_000_000_000 }, maxFileBytes = max, keepFiles = keep)

    // ---- redaction --------------------------------------------------------------------------------

    @Test
    fun `secrets, codes, emails and url paths are removed`() {
        val raw =
            "failed otpauth://totp/Ex:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Ex for alice@example.com " +
                "at https://user:pw@otp.example.org:8443/otp/v1/vault/commit?since=3 code 123456 secret JBSWY3DPEHPK3PXPJBSWY3DP " +
                "token uoe_abcdefghijklmnop device dev_AAAAAAAAAAAAAAAAAAAAAA item 7d444840-9dc0-11d1-b245-5ffdce74fad2 from 192.168.1.20"
        val out = Redactor.redact(raw)
        val leaks = listOf("JBSWY3DP", "alice", "example.com", "pw@", "/otp/v1", "since=3", "123456")
        for (leak in leaks + listOf("uoe_abc", "dev_AAAA", "7d444840", "192.168")) {
            assertFalse(leak in out, "$leak leaked: $out")
        }
        assertTrue("https://otp.example.org:8443/<redacted>" in out, out)
    }

    @Test
    fun `ordinary words and short numbers are kept`() {
        val text = "sync finished: 3 committed, 0 conflicts, version 12 in 250 ms"
        assertEquals(text, Redactor.redact(text))
    }

    @Test
    fun `stack traces keep class names and frames but not message content`() {
        val e = IllegalStateException("bad secret JBSWY3DPEHPK3PXPJBSWY3DP for bob@example.org")
        val out = Redactor.redactTrace(e)
        assertTrue("IllegalStateException" in out)
        assertTrue("DiagnosticsLogTest" in out)
        assertFalse("JBSWY3DP" in out)
        assertFalse("bob@" in out)
    }

    // ---- log ---------------------------------------------------------------------------------------

    @Test
    fun `events stay in memory, errors and crashes reach the file with the recent events`() {
        val l = log()
        l.event("sync", "started")
        assertFalse(File(dir, "errors.log").exists())
        l.error("sync", "pull failed for bob@example.org", RuntimeException("code 654321"))
        val text = l.export()
        assertTrue(text.startsWith("UltimateOTP diagnostics"))
        assertTrue("0.2.0 (4) release" in text)
        assertTrue("r8-map-id-1a2b3c" in text)
        assertTrue("[ERROR] sync" in text)
        assertTrue("sync: started" in text)
        assertFalse("bob@" in text)
        assertFalse("654321" in text)
        l.recordCrash("main", IllegalStateException("boom"))
        assertTrue("[CRASH]" in l.export())
    }

    @Test
    fun `the file is capped and rotated`() {
        val l = log(max = 2_000, keep = 2)
        repeat(200) { l.error("t", "entry number $it with some padding text to take space and more text") }
        assertTrue(l.sizeBytes() <= 2 * 2_000)
        assertTrue(File(dir, "errors.1.log").exists())
        assertFalse(File(dir, "errors.2.log").exists())
        val text = l.export()
        assertTrue("entry number 199" in text) // the newest survives
        assertFalse("entry number 0 " in text) // the oldest was dropped
    }

    @Test
    fun `a huge single entry is truncated, not stored whole`() {
        val l = log(max = 4_000)
        l.error("t", "x".repeat(100_000).chunked(7).joinToString(" "))
        assertTrue(l.sizeBytes() <= 4_000)
    }

    @Test
    fun `the ring is bounded and clear removes everything`() {
        val l = DiagnosticsLog(dir, build, ringSize = 5)
        repeat(50) { l.event("c", "event $it") }
        l.error("c", "now")
        val text = l.export()
        assertFalse("event 10" in text)
        assertTrue("event 49" in text)
        l.clear()
        assertEquals(0L, l.sizeBytes())
        assertTrue("(no errors recorded)" in l.export())
    }

    @Test
    fun `uncaught exceptions are recorded and passed on`() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        var passed: Throwable? = null
        Thread.setDefaultUncaughtExceptionHandler { _, t -> passed = t }
        try {
            val l = log()
            l.installCrashHandler()
            val t = Thread { throw IllegalArgumentException("kaboom 123456") }
            t.name = "worker-1"
            t.start()
            t.join()
            assertTrue(passed is IllegalArgumentException)
            val text = l.export()
            assertTrue("thread worker-1" in text)
            assertTrue("IllegalArgumentException" in text)
            assertFalse("123456" in text)
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous)
        }
    }
}
