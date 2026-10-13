// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import android.annotation.SuppressLint
import android.app.Activity
import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import androidx.core.content.edit
import java.util.Locale

/**
 * The app's language, "" for the system's. On Android 13+ it is the system's per-app language
 * (`LocaleManager`, also shown in the system settings). Before that, the choice is kept in a small
 * preferences file and applied by [wrap] in `attachBaseContext`, which needs no AppCompat theme.
 */
object AppLanguage {
    /** The languages that have a `values-xx` folder, as BCP 47 tags; "" is "system default". */
    val SUPPORTED = listOf("en", "es")

    private const val PREFS = "language"
    private const val KEY = "tag"

    /** The chosen tag: one of [SUPPORTED], or "" for the system language. */
    fun current(context: Context): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context
                .getSystemService(LocaleManager::class.java)
                ?.applicationLocales
                ?.takeIf { !it.isEmpty }
                ?.get(0)
                ?.language
                .orEmpty()
        } else {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, "").orEmpty()
        }

    /** Applies [tag]; the activity is recreated with the new language. */
    fun set(
        activity: Activity,
        tag: String,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.getSystemService(LocaleManager::class.java)?.applicationLocales =
                if (tag.isEmpty()) LocaleList.getEmptyLocaleList() else LocaleList.forLanguageTags(tag)
        } else {
            activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { putString(KEY, tag) }
            activity.recreate()
        }
    }

    /**
     * Before Android 13: the base context with the chosen language, else [base] as it is.
     * The check is about app bundles splitting languages (Play Core); this app ships one APK with all of them.
     */
    @SuppressLint("AppBundleLocaleChanges")
    fun wrap(base: Context): Context {
        val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) "" else current(base)
        return if (tag.isEmpty()) {
            base
        } else {
            val locale = Locale.forLanguageTag(tag)
            Locale.setDefault(locale)
            val config = Configuration(base.resources.configuration).apply { setLocale(locale) }
            base.createConfigurationContext(config)
        }
    }
}
