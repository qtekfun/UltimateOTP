// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import com.qtekfun.ultimateotp.core.support.autofill.FieldInfo
import com.qtekfun.ultimateotp.core.support.autofill.OtpFieldDetector

/** A field that looks like it asks for a one-time code, and where the form comes from. */
class ParsedForm(
    val fields: List<AutofillId>,
    val packageName: String?,
    val webDomain: String?,
)

/**
 * Reads the autofill structure for OTP fields. Only attributes that describe a field (hints,
 * ids, labels, input type) are read; the text a user typed is never touched.
 */
object StructureParser {
    fun parse(structure: AssistStructure): ParsedForm {
        val hits = mutableListOf<Pair<Int, AutofillId>>()
        var domain: String? = null
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode) { node ->
                if (domain == null) domain = node.webDomain?.takeIf { it.isNotBlank() }
                val id = node.autofillId
                if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                    val score = OtpFieldDetector.score(describe(node))
                    if (score >= OtpFieldDetector.THRESHOLD) hits += score to id
                }
            }
        }
        val best = hits.maxOfOrNull { it.first }
        val ids = if (best == null) emptyList() else hits.filter { it.first == best }.map { it.second }
        return ParsedForm(ids, structure.activityComponent?.packageName, domain)
    }

    private fun walk(
        root: AssistStructure.ViewNode,
        visit: (AssistStructure.ViewNode) -> Unit,
    ) {
        val stack = ArrayDeque<AssistStructure.ViewNode>()
        stack.add(root)
        while (stack.isNotEmpty()) {
            val node = stack.removeLast()
            visit(node)
            for (c in 0 until node.childCount) stack.add(node.getChildAt(c))
        }
    }

    private fun describe(node: AssistStructure.ViewNode): FieldInfo {
        val html =
            node.htmlInfo
                ?.attributes
                ?.associate { it.first.lowercase() to it.second }
                .orEmpty()
        val type = node.inputType
        val klass = type and InputType.TYPE_MASK_CLASS
        val variation = type and InputType.TYPE_MASK_VARIATION
        val numeric = klass == InputType.TYPE_CLASS_NUMBER || html["inputmode"] == "numeric" || html["type"] == "number"
        val password =
            (klass == InputType.TYPE_CLASS_TEXT && variation in TEXT_PASSWORDS) ||
                (klass == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) ||
                html["type"] == "password"
        return FieldInfo(
            autofillHints = node.autofillHints?.toList().orEmpty(),
            idEntry = node.idEntry,
            hint = node.hint,
            label = node.contentDescription?.toString() ?: html["aria-label"] ?: html["name"] ?: html["id"],
            htmlAutocomplete = html["autocomplete"],
            htmlType = html["type"],
            numeric = numeric,
            password = password,
            maxLength = html["maxlength"]?.toIntOrNull(),
        )
    }

    private val TEXT_PASSWORDS =
        setOf(
            InputType.TYPE_TEXT_VARIATION_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
        )
}
