// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.autofill

import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Offers the OTP code in fields that ask for one (docs/autofill.md). It never saves anything:
 * no `SaveInfo` is ever set, [onSaveRequest] is a no-op, and field contents are not read. A code
 * is only produced after the vault is unlocked (device credential or biometrics), when the user
 * picks the dataset.
 */
@AndroidEntryPoint
class UotpAutofillService : AutofillService() {
    @Inject lateinit var vault: VaultRepository

    @Inject lateinit var diagnostics: DiagnosticsLog

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val job =
            scope.launch {
                val response =
                    try {
                        structure?.let { respond(it) }
                    } catch (e: IllegalStateException) {
                        diagnostics.error("autofill", "fill request failed", e)
                        null
                    }
                callback.onSuccess(response)
            }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    private suspend fun respond(structure: android.app.assist.AssistStructure): FillResponse? {
        val form = StructureParser.parse(structure)
        if (form.fields.isEmpty()) return null
        diagnostics.event("autofill", "otp field found, vault ${vault.state.value}")
        return when (vault.state.value) {
            VaultState.NONE -> {
                null
            }

            VaultState.LOCKED -> {
                AutofillResponses.unlockResponse(this, form.fields, form.packageName, form.webDomain)
            }

            VaultState.UNLOCKED -> {
                val matches = AutofillResponses.matches(vault.items.first(), form.packageName, form.webDomain, packageName)
                AutofillResponses.datasetsResponse(this, matches, form.fields)
            }
        }
    }

    /** Nothing is ever offered for saving; if the framework asks anyway, nothing is kept. */
    override fun onSaveRequest(
        request: SaveRequest,
        callback: SaveCallback,
    ) {
        callback.onSuccess()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
