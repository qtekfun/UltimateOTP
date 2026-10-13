// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.screenshots

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.dp
import com.github.takahirom.roborazzi.captureRoboImage
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import com.qtekfun.ultimateotp.ui.add.AddContent
import com.qtekfun.ultimateotp.ui.codes.AddMode
import com.qtekfun.ultimateotp.ui.codes.AddSheetContent
import com.qtekfun.ultimateotp.ui.codes.CodesActions
import com.qtekfun.ultimateotp.ui.codes.CodesContent
import com.qtekfun.ultimateotp.ui.codes.CodesUi
import com.qtekfun.ultimateotp.ui.codes.ItemMenuContent
import com.qtekfun.ultimateotp.ui.codes.SyncIndicator
import com.qtekfun.ultimateotp.ui.components.currentWidthClass
import com.qtekfun.ultimateotp.ui.edit.EditContent
import com.qtekfun.ultimateotp.ui.lock.LockContent
import com.qtekfun.ultimateotp.ui.lock.WelcomeContent
import com.qtekfun.ultimateotp.ui.settings.SettingsActions
import com.qtekfun.ultimateotp.ui.settings.SettingsContent
import com.qtekfun.ultimateotp.ui.sync.LoginContent
import com.qtekfun.ultimateotp.ui.sync.LoginStep
import com.qtekfun.ultimateotp.ui.sync.SessionsContent
import com.qtekfun.ultimateotp.ui.sync.SignupContent
import com.qtekfun.ultimateotp.ui.sync.SignupStep
import com.qtekfun.ultimateotp.ui.theme.UotpTheme
import com.qtekfun.ultimateotp.util.Settings
import com.qtekfun.ultimateotp.util.ThemeMode
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** One device and look to render every screen in. */
data class Look(
    val name: String,
    val qualifiers: String,
    val dark: Boolean,
    val fontScale: Float = 1f,
    val amoled: Boolean = false,
) {
    override fun toString() = name
}

/**
 * Renders every screen on the JVM (Robolectric native graphics) into `build/screenshots/<look>/`,
 * so the design can be reviewed without a device. Not compared against goldens.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(application = android.app.Application::class, sdk = [34])
class ScreenshotTest(
    private val look: Look,
) {
    companion object {
        private const val PHONE = "w411dp-h914dp-420dpi"
        private const val COVER = "w443dp-h994dp-390dpi"
        private const val INNER = "w852dp-h883dp-390dpi"

        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0}")
        fun looks(): List<Look> =
            listOf(
                Look("phone-dark", PHONE, dark = true),
                Look("phone-light", PHONE, dark = false),
                Look("phone-amoled", PHONE, dark = true, amoled = true),
                Look("phone-dark-font1.3", PHONE, dark = true, fontScale = 1.3f),
                Look("phone-light-font2.0", PHONE, dark = false, fontScale = 2.0f),
                Look("cover-dark", COVER, dark = true),
                Look("inner-dark", INNER, dark = true),
                Look("inner-light", INNER, dark = false),
                Look("phone-es-dark", "es-$PHONE", dark = true),
                Look("phone-es-light-font1.3", "es-$PHONE", dark = false, fontScale = 1.3f),
                Look("cover-es-dark-font1.3", "es-$COVER", dark = true, fontScale = 1.3f),
                Look("inner-es-dark", "es-$INNER", dark = true),
            )
    }

    @get:Rule val rule = createComposeRule()

    private fun shot(
        name: String,
        content: @Composable () -> Unit,
    ) {
        RuntimeEnvironment.setQualifiers(look.qualifiers)
        RuntimeEnvironment.setFontScale(look.fontScale)
        rule.setContent {
            UotpTheme(mode = if (look.dark) ThemeMode.DARK else ThemeMode.LIGHT, amoled = look.amoled) {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { content() }
            }
        }
        rule.onRoot().captureRoboImage("build/screenshots/${look.name}/$name.png")
    }

    private fun codes(
        items: List<VaultItem> = Fixtures.items,
        ui: CodesUi = CodesUi(sync = SyncIndicator.SYNCED),
        now: Long = Fixtures.NOW,
    ): @Composable () -> Unit =
        {
            CodesContent(items = items, now = now, ui = ui, on = CodesActions(), widthClass = currentWidthClass())
        }

    @Test fun codesPopulated() = shot("codes-populated", codes())

    @Test fun codesEmpty() = shot("codes-empty", codes(items = emptyList(), ui = CodesUi()))

    @Test fun codesSearch() = shot("codes-search", codes(ui = CodesUi(searching = true, query = "pro", sync = SyncIndicator.SYNCED)))

    @Test fun codesTagFilter() = shot("codes-tag-work", codes(ui = CodesUi(tag = "Work", sync = SyncIndicator.OFFLINE)))

    @Test fun codesGrid() = shot("codes-grid", codes(ui = CodesUi(grid = true, sync = SyncIndicator.SYNCING)))

    @Test fun codesCopied() =
        shot(
            "codes-copied",
            codes(ui = CodesUi(copiedId = Fixtures.items[2].id, selectedId = Fixtures.items[2].id, sync = SyncIndicator.SYNCED)),
        )

    @Test fun addSheet() =
        shot("add-sheet") {
            Box(Modifier.fillMaxSize()) {
                codes(ui = CodesUi(sync = SyncIndicator.SYNCED))()
                SheetOver { AddSheetContent(onChoose = {}) }
            }
        }

    @Test fun itemMenu() =
        shot("item-menu") {
            Box(Modifier.fillMaxSize()) {
                codes()()
                SheetOver {
                    ItemMenuContent(Fixtures.items[7], onEdit = {}, onPin = {}, onTags = {}, onNext = {}, onDelete = {})
                }
            }
        }

    @Test fun addManual() = shot("add-manual") { AddScreenFor(AddMode.MANUAL) }

    @Test fun addScan() = shot("add-scan-permission") { AddScreenFor(AddMode.SCAN) }

    @Test fun addImport() = shot("add-import") { AddScreenFor(AddMode.IMPORT) }

    @Composable
    private fun AddScreenFor(mode: AddMode) {
        AddContent(
            mode = mode,
            onMode = {},
            invalid = false,
            cameraGranted = false,
            onAllowCamera = {},
            onPickImage = {},
            onPickFile = {},
            fileStatus = null,
            onFilePassword = {},
            onFilePasswordDismiss = {},
            onText = {},
            onAddManual = {},
            onBack = {},
            scanner = {},
        )
    }

    @Test fun edit() = shot("edit") { EditContent(Fixtures.items[0], onSave = {}, onDelete = {}, onBack = {}) }

    @Test fun welcome() = shot("welcome") { WelcomeContent(onChoice = {}, widthClass = currentWidthClass()) }

    @Test fun lock() = shot("lock") { LockContent(error = null, onUnlock = {}) }

    @Test fun lockError() = shot("lock-error") { LockContent(error = "Authentication was cancelled", onUnlock = {}) }

    @Test fun signupEmail() = shot("signup-1-email") { SignupFor(SignupStep.Email) }

    @Test fun signupCode() = shot("signup-2-code") { SignupFor(SignupStep.Code("alice@example.org", resendAt = Long.MAX_VALUE / 2)) }

    @Test fun signupPassword() = shot("signup-3-password") { SignupFor(SignupStep.Password) }

    @Test fun signupRecovery() = shot("signup-4-recovery") { SignupFor(SignupStep.Recovery(Fixtures.words)) }

    @Test fun signupWorking() = shot("signup-working") { SignupFor(SignupStep.Working(deriving = true)) }

    @Test fun signupDone() = shot("signup-5-done") { SignupFor(SignupStep.Done) }

    @Composable
    private fun SignupFor(step: SignupStep) {
        SignupContent(
            step = step,
            defaultServer = "https://otp.example.org",
            onBack = {},
            onLogin = {},
            onSendCode = { _, _ -> },
            onCode = {},
            onResend = {},
            onPassword = {},
            onRecoveryConfirmed = {},
            onRetry = {},
            onRestart = {},
            onCopyWords = {},
        )
    }

    @Test fun loginEmail() = shot("login-1-email") { LoginFor(LoginStep.Email()) }

    @Test fun loginEmailWrong() = shot("login-1-email-wrong") { LoginFor(LoginStep.Email(wrongPassword = true)) }

    @Test fun settings() =
        shot("settings") {
            SettingsContent(
                settings = Settings(),
                statusText = null,
                version = "0.2.0",
                language = "",
                actions = SettingsActions(),
            )
        }

    @Test fun sessions() =
        shot("sessions") {
            SessionsContent(
                hasAccount = true,
                devices = Fixtures.devices,
                sessions = Fixtures.sessions,
                onTrust = {},
                onRevoke = {},
                onBack = {},
            )
        }

    @Composable
    private fun LoginFor(step: LoginStep) {
        LoginContent(
            step = step,
            defaultServer = "https://otp.example.org",
            onBack = {},
            onSendCode = { _, _ -> },
            onVerify = { _, _ -> },
            onResend = {},
            onPassword = { _, _ -> },
            onRestart = {},
        )
    }
}

@Composable
private fun SheetOver(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.4f)), contentAlignment = Alignment.BottomCenter) {
        Surface(
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerLow,
        ) { content() }
    }
}
