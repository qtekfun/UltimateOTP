// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.qtekfun.ultimateotp.ui.AppRoot
import com.qtekfun.ultimateotp.ui.theme.UotpTheme
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.MutableStateFlow

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    /** A link this activity was opened with (`otpauth://`, `uotp://pair`, `uotp://enroll`). */
    private val pendingLink = MutableStateFlow<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, no preview in the recents screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        pendingLink.value = intent?.dataString
        setContent {
            UotpTheme {
                AppRoot(authenticate = ::authenticate, pendingLink = pendingLink)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pendingLink.value = intent.dataString
    }

    /** The app lock: biometrics or the device credential, which also unlocks the Keystore key. */
    private fun authenticate(
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        val authenticators =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                BIOMETRIC_STRONG or DEVICE_CREDENTIAL
            } else {
                BIOMETRIC_WEAK or DEVICE_CREDENTIAL
            }
        val info =
            BiometricPrompt.PromptInfo
                .Builder()
                .setTitle(getString(R.string.unlock_title))
                .setSubtitle(getString(R.string.unlock_subtitle))
                .setAllowedAuthenticators(authenticators)
                .build()
        val prompt =
            BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence,
                    ) = onError(errString.toString())
                },
            )
        prompt.authenticate(info)
    }
}
