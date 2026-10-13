// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.di

import android.content.Context
import android.util.Log
import com.qtekfun.ultimateotp.BuildConfig
import com.qtekfun.ultimateotp.core.support.diag.BuildDescription
import com.qtekfun.ultimateotp.core.support.diag.DiagnosticsLog
import com.qtekfun.ultimateotp.core.sync.account.AccountManagement
import com.qtekfun.ultimateotp.core.sync.history.HistoryRecovery
import com.qtekfun.ultimateotp.core.sync.login.EmailLogin
import com.qtekfun.ultimateotp.core.sync.login.EmailSignup
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultTransfer
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.KeystoreSecretStore
import com.qtekfun.ultimateotp.core.vault.secure.SecretStore
import com.qtekfun.ultimateotp.sync.AccountRefresh
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.util.BuildInfo
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import javax.inject.Qualifier
import javax.inject.Singleton

/** Scope of work that must outlive a screen (clipboard clearing, sync). */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class AppScope

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides
    @Singleton
    fun database(
        @ApplicationContext context: Context,
    ): VaultDatabase = VaultDatabase.create(context)

    @Provides
    @Singleton
    fun secrets(
        @ApplicationContext context: Context,
    ): SecretStore = KeystoreSecretStore(context)

    @Provides
    @Singleton
    fun vault(
        db: VaultDatabase,
        secrets: SecretStore,
    ): VaultRepository = VaultRepository(db.dao(), secrets)

    @Provides
    @Singleton
    fun transfer(vault: VaultRepository): VaultTransfer = VaultTransfer(vault)

    /** Email code + SRP-6a login (contract 1.1.0, decisions 6 and 13). */
    @Provides
    @Singleton
    fun emailLogin(sync: SyncController): EmailLogin = SrpEmailLogin(sync.engine, sync::api)

    /** Public sign-up (contract 1.1.0 `/signup`), like Ente Auth's account creation. */
    @Provides
    @Singleton
    fun emailSignup(sync: SyncController): EmailSignup = EmailSignup(sync.engine, sync::api)

    /** Account routes of contract 1.2.0: delete account, change email, sign out others, export. */
    @Provides
    @Singleton
    fun accountManagement(
        vault: VaultRepository,
        sync: SyncController,
    ): AccountManagement = AccountManagement(vault, sync.engine, sync::api)

    /** The server's trash and version history (contract 1.2.0). */
    @Provides
    @Singleton
    fun historyRecovery(
        vault: VaultRepository,
        sync: SyncController,
    ): HistoryRecovery = HistoryRecovery(vault, sync.engine, sync::api)

    /** Local error log (docs/diagnostics.md): private file, no network. */
    @Provides
    @Singleton
    fun diagnostics(
        @ApplicationContext context: Context,
    ): DiagnosticsLog =
        DiagnosticsLog(
            java.io.File(context.filesDir, "diagnostics"),
            BuildDescription(
                appVersion = BuildConfig.VERSION_NAME,
                versionCode = BuildConfig.VERSION_CODE,
                buildType = BuildConfig.BUILD_TYPE,
                mapId = BuildInfo.mapId(),
                androidSdk = android.os.Build.VERSION.SDK_INT,
            ),
        )

    @Provides
    fun accountRefresh(sync: SyncController): AccountRefresh = AccountRefresh { sync.refresh() }

    @Provides
    @Singleton
    @AppScope
    fun appScope(): CoroutineScope =
        CoroutineScope(
            SupervisorJob() + Dispatchers.Default +
                CoroutineExceptionHandler { _, e -> Log.e("UotpApp", "background work failed: ${e.javaClass.simpleName}") },
        )
}
