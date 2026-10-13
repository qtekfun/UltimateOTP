// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.support.autofill.AutofillCandidate
import com.qtekfun.ultimateotp.core.support.autofill.AutofillMatcher
import com.qtekfun.ultimateotp.core.sync.model.VaultItem

/** What the unlock step and the dataset step of autofill are asked to do. */
internal object AutofillResponses {
    const val MODE_UNLOCK = "unlock"
    const val MODE_DATASET = "dataset"

    fun candidates(items: List<VaultItem>): List<AutofillCandidate> =
        items.map {
            AutofillCandidate(it.id.toString(), it.otp.issuer, it.autofill)
        }

    fun matches(
        items: List<VaultItem>,
        packageName: String?,
        webDomain: String?,
        ownPackage: String,
    ): List<VaultItem> {
        val byId = items.associateBy { it.id.toString() }
        // A web form is matched by its domain alone: the browser's own package says nothing.
        val pkg = if (webDomain != null) null else packageName
        return AutofillMatcher.match(candidates(items), pkg, webDomain, ownPackage).mapNotNull { byId[it.candidate.id] }
    }

    private fun presentation(
        context: Context,
        title: String,
        subtitle: String,
    ) = RemoteViews(context.packageName, R.layout.autofill_item).apply {
        setTextViewText(R.id.title, title)
        setTextViewText(R.id.subtitle, subtitle)
    }

    private fun authIntent(
        context: Context,
        requestCode: Int,
        configure: Intent.() -> Unit,
    ) = PendingIntent
        .getActivity(
            context,
            requestCode,
            Intent(context, AutofillAuthActivity::class.java).apply(configure),
            // The framework adds its own extras to an authentication intent, so it must be mutable.
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        ).intentSender

    /** The vault is locked: one entry asking to unlock; matching happens after unlocking. */
    @Suppress("DEPRECATION") // The presentation-based overload needs API 33; this one works on all.
    fun unlockResponse(
        context: Context,
        fields: List<AutofillId>,
        packageName: String?,
        webDomain: String?,
    ): FillResponse =
        FillResponse
            .Builder()
            .setAuthentication(
                fields.toTypedArray(),
                authIntent(context, UNLOCK_CODE) {
                    putExtra(AutofillAuthActivity.EXTRA_MODE, MODE_UNLOCK)
                    putExtra(AutofillAuthActivity.EXTRA_PACKAGE, packageName)
                    putExtra(AutofillAuthActivity.EXTRA_DOMAIN, webDomain)
                    putParcelableArrayListExtra(AutofillAuthActivity.EXTRA_FIELDS, ArrayList(fields))
                },
                presentation(context, context.getString(R.string.autofill_unlock), context.getString(R.string.app_name)),
            ).build()

    /**
     * One dataset per matching entry. A dataset carries no value: the code is made when the user
     * picks it, after [AutofillAuthActivity] has checked that the app is unlocked, so no code
     * ever sits in a response and each is fresh. Only issuer and account are shown.
     */
    @Suppress("DEPRECATION") // setValue is the only way below API 33, and still works above it.
    fun datasetsResponse(
        context: Context,
        matches: List<VaultItem>,
        fields: List<AutofillId>,
    ): FillResponse? {
        if (matches.isEmpty() || fields.isEmpty()) return null
        val builder = FillResponse.Builder()
        matches.forEachIndexed { index, item ->
            val dataset =
                Dataset
                    .Builder(
                        presentation(
                            context,
                            context.getString(R.string.autofill_dataset, item.otp.issuer.ifBlank { item.otp.label }),
                            context.getString(R.string.autofill_dataset_sub, item.otp.label),
                        ),
                    ).setAuthentication(
                        authIntent(context, DATASET_CODE + index) {
                            putExtra(AutofillAuthActivity.EXTRA_MODE, MODE_DATASET)
                            putExtra(AutofillAuthActivity.EXTRA_ITEM, item.id.toString())
                            putParcelableArrayListExtra(AutofillAuthActivity.EXTRA_FIELDS, ArrayList(fields))
                        },
                    )
            fields.forEach { dataset.setValue(it, null) }
            builder.addDataset(dataset.build())
        }
        return builder.build()
    }

    private const val UNLOCK_CODE = 7000
    private const val DATASET_CODE = 7100
}
