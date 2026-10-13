// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.content.Context
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.sync.fake.FakeUotpServer
import com.qtekfun.ultimateotp.core.sync.fake.InMemorySyncStore
import com.qtekfun.ultimateotp.ui.theme.UotpTheme
import okhttp3.OkHttpClient
import org.junit.Assert.assertTrue
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController

/** Window sizes of a Pixel 9 Pro Fold, in dp at 420 dpi (1080 x 2424 px and 2076 x 2152 px). */
enum class Screen(
    val qualifiers: String,
    val widthDp: Int,
) {
    /** The cover display, folded: a tall, narrow phone. */
    COVER("w411dp-h923dp-420dpi", 411),

    /** The inner display, unfolded: nearly square, tablet-sized. */
    INNER("w791dp-h820dp-420dpi", 791),
}

fun string(id: Int): String = ApplicationProvider.getApplicationContext<Context>().getString(id)

fun string(
    id: Int,
    vararg args: Any,
): String = ApplicationProvider.getApplicationContext<Context>().getString(id, *args)

/**
 * A `ComponentActivity` standing in for `MainActivity`: Robolectric builds it directly (no
 * manifest entry), the content is set in the same place `MainActivity.onCreate` sets it, and
 * [configurationChange] does what rotating or unfolding the phone does: destroys the activity,
 * keeps its `ViewModelStore` and saved state, creates a new instance and sets the content again.
 */
class Host(
    private val rule: ComposeTestRule,
    private val content: @Composable () -> Unit,
) {
    var controller: ActivityController<ComponentActivity> = Robolectric.buildActivity(ComponentActivity::class.java)
        private set
    var activity: ComponentActivity? = null
        private set
    var recreations = 0
        private set

    fun start(screen: Screen) {
        RuntimeEnvironment.setQualifiers("+${screen.qualifiers}")
        controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        show()
    }

    private fun show() {
        val current = controller.get()
        activity = current
        current.setContent { UotpTheme { content() } }
        rule.waitForIdle()
    }

    /** Rotation, fold or unfold: a new size and a new activity instance, state restored. */
    fun configurationChange(to: Screen? = null) {
        if (to != null) RuntimeEnvironment.setQualifiers("+${to.qualifiers}")
        controller = controller.recreate()
        recreations++
        show()
    }

    fun widthDp(): Int = requireNotNull(activity).resources.configuration.screenWidthDp
}

/** Texts, buttons and fields by what the user sees. */
class Ui(
    private val rule: ComposeTestRule,
) {
    fun see(text: String) {
        rule.onNodeWithText(text).assertExists("expected '$text' on screen")
    }

    fun notSee(text: String) {
        assertTrue("did not expect '$text'", rule.onAllNodesWithText(text).fetchSemanticsNodes().isEmpty())
    }

    fun tap(text: String) {
        rule.onNodeWithText(text).performClick()
    }

    /** Text fields in reading order; `OutlinedTextField` labels are not their text. */
    fun type(
        index: Int,
        value: String,
    ) {
        rule.onAllNodes(hasSetTextAction())[index].performTextInput(value)
    }

    fun fieldCount(): Int = rule.onAllNodes(hasSetTextAction()).fetchSemanticsNodes().size

    fun waitFor(
        text: String,
        timeoutMs: Long = WAIT_MS,
    ) {
        rule.waitUntil(timeoutMs) { rule.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
    }

    private companion object {
        const val WAIT_MS = 30_000L
    }
}

/** Real engine and crypto against the contract fake server; Argon2id at a cheap rung. */
class FakeBackend(
    signup: Boolean = true,
    accountExists: Boolean = false,
) : AutoCloseable {
    val server = FakeUotpServer(signupEnabled = signup, accountExists = accountExists)
    val store = InMemorySyncStore()
    val apiFor = { url: String -> UotpApi(url, OkHttpClient(), nowSeconds = { server.now }) }
    val engine = SyncEngine(store, apiFor, kdfLadder = { listOf(2L to (16L shl 20)) })

    override fun close() = server.close()
}
