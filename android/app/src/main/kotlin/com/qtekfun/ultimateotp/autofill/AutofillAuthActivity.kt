// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.autofill

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.otp.OtpGenerator
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * The authentication step of autofill. Locked vault: asks for biometrics or the device
 * credential, then answers with the matching datasets. A picked dataset: makes the code now and
 * returns it as the result. Nothing is shown of its own and nothing is stored.
 */
@AndroidEntryPoint
class AutofillAuthActivity : FragmentActivity() {
    @Inject lateinit var vault: VaultRepository

    @Inject lateinit var diagnostics: DiagnosticsLog

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        lifecycleScope.launch {
            val ok =
                try {
                    ensureUnlocked()
                } catch (e: IllegalStateException) {
                    diagnostics.error("autofill", "unlock failed", e)
                    false
                }
            val result = if (ok) buildResult() else null
            if (result == null) {
                setResult(Activity.RESULT_CANCELED)
            } else {
                setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, result))
            }
            finish()
        }
    }

    private suspend fun ensureUnlocked(): Boolean {
        when (vault.state.value) {
            VaultState.UNLOCKED -> return true
            VaultState.NONE -> return false
            VaultState.LOCKED -> Unit
        }
        try {
            vault.unlock()
        } catch (_: AuthenticationRequiredException) {
            if (!prompt()) return false
            vault.unlock()
        }
        return vault.state.value == VaultState.UNLOCKED
    }

    private suspend fun prompt(): Boolean =
        suspendCoroutine { cont ->
            val authenticators =
                if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.R
                ) {
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
            BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = cont.resume(true)

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence,
                    ) = cont.resume(false)
                },
            ).authenticate(info)
        }

    @Suppress("DEPRECATION") // See AutofillResponses.datasetsResponse.
    private suspend fun buildResult(): android.os.Parcelable? {
        val fields = intent.getParcelableArrayListExtra<AutofillId>(EXTRA_FIELDS).orEmpty()
        if (fields.isEmpty()) return null
        val items = vault.items.first()
        return when (intent.getStringExtra(EXTRA_MODE)) {
            AutofillResponses.MODE_UNLOCK -> {
                val matches =
                    AutofillResponses.matches(
                        items,
                        intent.getStringExtra(EXTRA_PACKAGE),
                        intent.getStringExtra(EXTRA_DOMAIN),
                        packageName,
                    )
                AutofillResponses.datasetsResponse(this, matches, fields)
            }

            AutofillResponses.MODE_DATASET -> {
                val id = runCatching { UUID.fromString(intent.getStringExtra(EXTRA_ITEM)) }.getOrNull() ?: return null
                val item = items.firstOrNull { it.id == id } ?: return null
                // HOTP: the counter is stored before the code is shown, like on the codes screen.
                val live = if (item.otp.type == OtpType.HOTP) vault.nextHotpCounter(id) ?: return null else item
                val code = OtpGenerator.code(live.otp, System.currentTimeMillis())
                val views = android.widget.RemoteViews(packageName, R.layout.autofill_item)
                val dataset = Dataset.Builder(views)
                fields.forEach { dataset.setValue(it, AutofillValue.forText(code)) }
                dataset.build()
            }

            else -> {
                null
            }
        }
    }

    companion object {
        const val EXTRA_MODE = "mode"
        const val EXTRA_ITEM = "item"
        const val EXTRA_FIELDS = "fields"
        const val EXTRA_PACKAGE = "package"
        const val EXTRA_DOMAIN = "domain"
    }
}
