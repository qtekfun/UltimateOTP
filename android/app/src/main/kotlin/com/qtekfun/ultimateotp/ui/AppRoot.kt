// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import com.qtekfun.ultimateotp.ui.add.AddScreen
import com.qtekfun.ultimateotp.ui.codes.CodesScreen
import com.qtekfun.ultimateotp.ui.edit.EditScreen
import com.qtekfun.ultimateotp.ui.lock.LockScreen
import com.qtekfun.ultimateotp.ui.lock.WelcomeScreen
import com.qtekfun.ultimateotp.ui.settings.SettingsScreen
import com.qtekfun.ultimateotp.ui.sync.LoginScreen
import com.qtekfun.ultimateotp.ui.sync.SyncScreen
import com.qtekfun.ultimateotp.ui.sync.deviceLabel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Shows the lock or welcome screen until the vault is unlocked, then the app's screens. */
@HiltViewModel
class RootViewModel
    @Inject
    constructor(
        val vault: VaultRepository,
    ) : ViewModel() {
        val state: StateFlow<VaultState> = vault.state

        fun create() = viewModelScope.launch { vault.create() }
    }

typealias Authenticate = (onSuccess: () -> Unit, onError: (String) -> Unit) -> Unit

@Composable
fun AppRoot(
    authenticate: Authenticate,
    pendingLink: MutableStateFlow<String?>,
    model: RootViewModel = hiltViewModel(),
) {
    val state by model.state.collectAsState()
    when (state) {
        VaultState.NONE -> WelcomeScreen(onCreate = model::create)
        VaultState.LOCKED -> LockScreen(authenticate)
        VaultState.UNLOCKED -> Unlocked(pendingLink)
    }
}

@Composable
private fun Unlocked(pendingLink: MutableStateFlow<String?>) {
    val nav = rememberNavController()
    val link by pendingLink.collectAsState()
    LaunchedEffect(link) {
        val l = link ?: return@LaunchedEffect
        pendingLink.value = null
        when {
            l.startsWith("otpauth", ignoreCase = true) -> nav.navigate("add?link=${android.net.Uri.encode(l)}")
            l.startsWith("uotp://", ignoreCase = true) -> nav.navigate("sync?link=${android.net.Uri.encode(l)}")
        }
    }
    NavHost(navController = nav, startDestination = "codes") {
        composable("codes") {
            CodesScreen(
                onAdd = { nav.navigate("add?link=") },
                onEdit = { id -> nav.navigate("edit/$id") },
                onSettings = { nav.navigate("settings") },
            )
        }
        composable(
            "add?link={link}",
            arguments =
                listOf(
                    navArgument("link") {
                        type = NavType.StringType
                        defaultValue = ""
                    },
                ),
        ) {
            AddScreen(
                initialLink = it.arguments?.getString("link").orEmpty(),
                onDone = { nav.popBackStack() },
                onSyncLink = { l -> nav.navigate("sync?link=${android.net.Uri.encode(l)}") },
            )
        }
        composable("edit/{id}") { EditScreen(id = it.arguments?.getString("id").orEmpty(), onDone = { nav.popBackStack() }) }
        composable("settings") { SettingsScreen(onBack = { nav.popBackStack() }, onSync = { nav.navigate("sync?link=") }) }
        composable(
            "sync?link={link}",
            arguments =
                listOf(
                    navArgument("link") {
                        type = NavType.StringType
                        defaultValue = ""
                    },
                ),
        ) {
            SyncScreen(
                initialLink = it.arguments?.getString("link").orEmpty(),
                onBack = { nav.popBackStack() },
                onLogin = { nav.navigate("login") },
            )
        }
        composable("login") { LoginScreen(defaultServer = "", label = deviceLabel(), onBack = { nav.popBackStack() }) }
    }
}
