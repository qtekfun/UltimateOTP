// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.di

import android.content.Context
import com.qtekfun.ultimateotp.core.sync.login.EmailLogin
import com.qtekfun.ultimateotp.core.sync.login.SrpEmailLogin
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultTransfer
import com.qtekfun.ultimateotp.core.vault.db.VaultDatabase
import com.qtekfun.ultimateotp.core.vault.secure.KeystoreSecretStore
import com.qtekfun.ultimateotp.core.vault.secure.SecretStore
import com.qtekfun.ultimateotp.sync.SyncController
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
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

    @Provides
    @Singleton
    @AppScope
    fun appScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
}
