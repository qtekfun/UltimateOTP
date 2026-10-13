// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.sync

import android.app.ActivityManager
import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.qtekfun.ultimateotp.BuildConfig
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.sync.AccountState
import com.qtekfun.ultimateotp.core.sync.EventStream
import com.qtekfun.ultimateotp.core.sync.SyncEngine
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import com.qtekfun.ultimateotp.di.AppScope
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/** What the sync screen and banners show. */
data class SyncStatus(
    val account: AccountState? = null,
    val running: Boolean = false,
    val last: SyncResult? = null,
    val offline: Boolean = false,
)

/**
 * Live sync (decision 1): while the app is in the foreground and unlocked, keeps the SSE stream
 * open and syncs on every `vault`/`devices` notification and shortly after every local edit.
 * Codes never wait for it: everything works offline.
 */
@Singleton
class SyncController
    @Inject
    constructor(
        @ApplicationContext private val context: Context,
        private val vault: VaultRepository,
        @AppScope private val scope: CoroutineScope,
        private val diagnostics: DiagnosticsLog,
    ) : DefaultLifecycleObserver {
        val http: OkHttpClient = OkHttpClient.Builder().callTimeout(CALL_TIMEOUT_S, TimeUnit.SECONDS).build()
        private val apis = mutableMapOf<String, UotpApi>()

        fun api(url: String): UotpApi =
            synchronized(apis) {
                apis.getOrPut(url) { UotpApi(url, http, appVersion = "UltimateOTP-Android/${BuildConfig.VERSION_NAME}") }
            }

        val engine = SyncEngine(vault, ::api, kdfLadder = ::ladder)
        private val _status = MutableStateFlow(SyncStatus())
        val status: StateFlow<SyncStatus> = _status.asStateFlow()
        private var foreground = false

        private val events =
            EventStream(
                http,
                api = { runBlocking { vault.account() }?.let { api(it.serverUrl) } },
                signer = { runCatching { runBlocking { vault.account() }?.let { Signer(vault.deviceKeys(), it.deviceId) } }.getOrNull() },
                onEvent = { event ->
                    when {
                        event.type in SYNC_EVENTS -> syncNow()

                        // The account was deleted from another device: keep the entries, forget the account.
                        event.type == "account_deleted" -> forgetAccount()
                    }
                },
            )

        /** Argon2id starts at the rung that fits in free memory (crypto-format.md §4.1). */
        fun ladder(): List<Pair<Long, Long>> {
            val info = ActivityManager.MemoryInfo()
            context.getSystemService(ActivityManager::class.java)?.getMemoryInfo(info)
            return PasswordKdf.ladderFor(info.availMem)
        }

        @OptIn(FlowPreview::class)
        fun start() {
            ProcessLifecycleOwner.get().lifecycle.addObserver(this)
            scope.launch {
                vault.state.collect {
                    // The trash empties itself after 30 days.
                    if (it == VaultState.UNLOCKED) runCatching { vault.purgeExpired() }
                    refresh()
                }
            }
            scope.launch { vault.items.debounce(EDIT_DEBOUNCE_MS).collect { if (hasAccount()) syncNow() } }
        }

        private suspend fun hasAccount(): Boolean = vault.state.value == VaultState.UNLOCKED && vault.account() != null

        override fun onStart(owner: LifecycleOwner) {
            foreground = true
            scope.launch { refresh() }
        }

        override fun onStop(owner: LifecycleOwner) {
            foreground = false
            events.stop()
        }

        /** Re-reads the account, starts or stops the live stream. */
        suspend fun refresh() {
            val account = if (vault.state.value == VaultState.UNLOCKED) vault.account() else null
            _status.value = _status.value.copy(account = account)
            if (account != null && foreground) {
                events.start(scope)
                syncNow()
            } else {
                events.stop()
            }
        }

        private suspend fun forgetAccount() {
            diagnostics.event("sync", "account deleted elsewhere")
            runCatching { vault.leaveAccount() }
            events.stop()
            refresh()
        }

        fun syncNow() {
            scope.launch {
                if (!hasAccount() || _status.value.running) return@launch
                _status.value = _status.value.copy(running = true)
                val result =
                    try {
                        engine.sync().also { _status.value = _status.value.copy(offline = false) }
                    } catch (_: IOException) {
                        _status.value = _status.value.copy(offline = true)
                        null
                    }
                diagnostics.event("sync", describe(result))
                _status.value = _status.value.copy(running = false, last = result ?: _status.value.last, account = vault.account())
                if (result == SyncResult.Revoked) events.stop()
            }
        }

        private fun describe(result: SyncResult?): String =
            when (result) {
                null -> "offline"
                is SyncResult.Synced -> "synced v${result.version}, ${result.committed} sent, ${result.conflicts} conflicts"
                SyncResult.Revoked -> "device revoked"
                else -> result.javaClass.simpleName
            }

        private companion object {
            const val CALL_TIMEOUT_S = 30L
            const val EDIT_DEBOUNCE_MS = 2_000L
            val SYNC_EVENTS = setOf("hello", "vault", "devices")
        }
    }
