// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.smoke

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until

/**
 * Drives the installed app the way a person does, through the accessibility tree, and knows
 * nothing about its classes. That is on purpose: the build under test is minified, so every class
 * and member the test might name has been renamed or removed; text on screen and the launcher
 * intent are the only stable interface, and they are the one a user has.
 *
 * Compose exposes `Text` as accessibility text and every `OutlinedTextField` as an `EditText`
 * (labels are not text of the node, so fields are addressed by their order on screen).
 */
class AppDriver {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    val device: UiDevice = UiDevice.getInstance(instrumentation)
    val context: Context = instrumentation.targetContext
    val packageName: String = context.packageName

    /** `http://10.0.2.2:<port>` (the emulator's alias for the host) unless CI says otherwise. */
    val serverUrl: String = InstrumentationRegistry.getArguments().getString("server") ?: "http://10.0.2.2:8047"

    /** Who signs up and logs in; the same in every journey, so a later run finds the earlier account. */
    val email: String = InstrumentationRegistry.getArguments().getString("email") ?: "smoke@example.org"
    val password: String = InstrumentationRegistry.getArguments().getString("password") ?: "correct horse battery staple"

    fun launch() {
        device.pressHome()
        val intent =
            requireNotNull(context.packageManager.getLaunchIntentForPackage(packageName)) { "no launcher activity in $packageName" }
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
        check(device.wait(Until.hasObject(By.pkg(packageName).depth(0)), LAUNCH_MS)) { "the app did not come to the foreground" }
    }

    fun has(text: String): Boolean = device.hasObject(By.text(text))

    /** Waits for [text] and returns its node, or fails with what is on screen instead. */
    fun waitFor(
        text: String,
        timeoutMs: Long = STEP_MS,
    ): UiObject2 = waitFor(By.text(text), timeoutMs, "text '$text'")

    fun waitFor(
        selector: BySelector,
        timeoutMs: Long = STEP_MS,
        what: String = selector.toString(),
    ): UiObject2 {
        val found = device.wait(Until.findObject(selector), timeoutMs)
        if (found == null) giveUp("Expected $what within ${timeoutMs / MILLIS} s. On screen: ${visibleText()}")
        return found
    }

    /** Scrolls the page up (content moves up) until [text] is on screen, at most [swipes] times. */
    fun scrollTo(
        text: String,
        swipes: Int = MAX_SWIPES,
    ): UiObject2 {
        repeat(swipes) {
            device.findObject(By.text(text))?.let { return it }
            val w = device.displayWidth
            val h = device.displayHeight
            device.swipe(w / 2, h * 3 / 4, w / 2, h / 4, SWIPE_STEPS)
        }
        return waitFor(text, SHORT_MS)
    }

    fun tap(text: String) = waitFor(text).click()

    fun tapAfterScrolling(text: String) = scrollTo(text).click()

    /** The text fields of the current screen, top to bottom. */
    fun fields(): List<UiObject2> {
        val all = device.findObjects(By.clazz("android.widget.EditText"))
        return all.sortedBy { it.visibleBounds.top }
    }

    fun fill(
        index: Int,
        value: String,
    ) {
        waitFor(By.clazz("android.widget.EditText"), STEP_MS, "a text field")
        val field = fields().getOrNull(index) ?: giveUp("no text field #$index. On screen: ${visibleText()}")
        field.click()
        field.text = value
    }

    /** Every text on screen, for failure messages (never secrets: the screens show none until asked). */
    fun visibleText(): String =
        device
            .findObjects(By.pkg(packageName))
            .mapNotNull { it.text ?: it.contentDescription }
            .filter { it.isNotBlank() }
            .joinToString(" | ")
            .ifEmpty { "(nothing from $packageName; foreground is ${device.currentPackageName})" }

    /** Fails if the process died or the system shows its crash or ANR dialog. */
    fun assertAlive(step: String) {
        val dialog = device.findObject(By.textContains("has stopped").pkg("android"))
        if (dialog != null) giveUp("The app crashed during '$step': system dialog '${dialog.text}'")
        val anr = device.findObject(By.textContains("isn't responding").pkg("android"))
        if (anr != null) giveUp("The app did not respond during '$step': system dialog '${anr.text}'")
        check(device.currentPackageName == packageName) {
            "After '$step' the foreground app is ${device.currentPackageName}, not $packageName. On screen: ${visibleText()}"
        }
    }

    private fun giveUp(message: String): Nothing = throw AssertionError(message)

    fun abis(): String = "${Build.SUPPORTED_ABIS.joinToString()} (api ${Build.VERSION.SDK_INT})"

    companion object {
        const val LAUNCH_MS = 30_000L
        const val STEP_MS = 15_000L
        const val SHORT_MS = 3_000L

        /** Argon2id at the sensitive rung plus SRP's 4096-bit arithmetic on an emulator. */
        const val DERIVE_MS = 180_000L
        private const val MAX_SWIPES = 6
        private const val SWIPE_STEPS = 20
        private const val MILLIS = 1000L
    }
}
