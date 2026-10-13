// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore by preferencesDataStore("settings")

/** Non-secret preferences. */
data class Settings(
    /** Seconds in the background before the vault locks; 0 = at once. */
    val lockTimeoutSeconds: Int = 60,
    val clipboardClearSeconds: Int = 30,
    /** Server base URL used for everything except enrollment when [enrollmentUrl] is set. */
    val serverUrl: String = "",
    /** LAN address of the same server, used for enrollment and recovery (decisions.md item 4). */
    val enrollmentUrl: String = "",
    /** Allow enrollment through [serverUrl] even if it is not a LAN address. Off by default. */
    val allowRemoteEnrollment: Boolean = false,
)

@Singleton
class AppSettings
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
    ) {
        private val lock = intPreferencesKey("lock_timeout_s")
        private val clip = intPreferencesKey("clipboard_clear_s")
        private val server = stringPreferencesKey("server_url")
        private val enroll = stringPreferencesKey("enrollment_url")
        private val remote = booleanPreferencesKey("allow_remote_enrollment")

        val settings: Flow<Settings> = context.dataStore.data.map { it.toSettings() }

        suspend fun current(): Settings = settings.first()

        private fun Preferences.toSettings() =
            Settings(
                lockTimeoutSeconds = this[lock] ?: Settings().lockTimeoutSeconds,
                clipboardClearSeconds = this[clip] ?: Settings().clipboardClearSeconds,
                serverUrl = this[server].orEmpty(),
                enrollmentUrl = this[enroll].orEmpty(),
                allowRemoteEnrollment = this[remote] ?: false,
            )

        suspend fun update(transform: (Settings) -> Settings) {
            context.dataStore.edit { prefs ->
                val next = transform(prefs.toSettings())
                prefs[lock] = next.lockTimeoutSeconds
                prefs[clip] = next.clipboardClearSeconds
                prefs[server] = next.serverUrl
                prefs[enroll] = next.enrollmentUrl
                prefs[remote] = next.allowRemoteEnrollment
            }
        }
    }
