// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
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
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.auth.AuthHost
import com.qtekfun.ultimateotp.auth.GateResult
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.core.vault.VaultState
import com.qtekfun.ultimateotp.features.AccountScreen
import com.qtekfun.ultimateotp.features.AutofillAssociationsScreen
import com.qtekfun.ultimateotp.features.TrashScreen
import com.qtekfun.ultimateotp.ui.add.AddScreen
import com.qtekfun.ultimateotp.ui.codes.AddMode
import com.qtekfun.ultimateotp.ui.codes.CodesScreen
import com.qtekfun.ultimateotp.ui.edit.EditScreen
import com.qtekfun.ultimateotp.ui.lock.LockScreen
import com.qtekfun.ultimateotp.ui.lock.WelcomeScreen
import com.qtekfun.ultimateotp.ui.settings.SettingsScreen
import com.qtekfun.ultimateotp.ui.sync.LoginScreen
import com.qtekfun.ultimateotp.ui.sync.SessionsScreen
import com.qtekfun.ultimateotp.ui.sync.SignupScreen
import com.qtekfun.ultimateotp.ui.sync.SyncScreen
import com.qtekfun.ultimateotp.ui.sync.deviceLabel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** The first-run choice (like Ente Auth's): where to go once the local vault exists. */
enum class FirstRun { SIGN_UP, LOG_IN, OFFLINE, ADVANCED }

/** Shows the lock or welcome screen until the vault is unlocked, then the app's screens. */
@HiltViewModel
class RootViewModel
    @Inject
    constructor(
        val vault: VaultRepository,
        val gate: AuthGate,
    ) : ViewModel() {
        val state: StateFlow<VaultState> = vault.state
        private val _firstRun = MutableStateFlow<FirstRun?>(null)
        val firstRun: StateFlow<FirstRun?> = _firstRun.asStateFlow()

        /**
         * Every path starts with the local vault (its key becomes the account's vault key on
         * sign-up or bootstrap, or receives the account's on login); then [choice] opens its screen.
         */
        fun create(choice: FirstRun) {
            if (creating) return
            creating = true
            viewModelScope.launch {
                try {
                    // The first write of the vault key may need the user to authenticate. If that
                    // is declined the person stays on the welcome screen with a message.
                    if (gate.attempt { vault.create() } is GateResult.Done) _firstRun.value = choice
                } finally {
                    creating = false
                }
            }
        }

        private var creating = false

        /** Unlocks the stored vault, asking the user to authenticate if the Keystore wants it. */
        fun unlock() {
            viewModelScope.launch { gate.attempt { vault.unlock() } }
        }

        fun firstRunShown() {
            _firstRun.value = null
        }
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
        VaultState.NONE -> WelcomeScreen(onChoice = model::create)
        VaultState.LOCKED -> LockScreen(model)
        VaultState.UNLOCKED -> Unlocked(pendingLink, model)
    }
    AuthHost(model.gate, authenticate)
}

private const val NAV_MS = 280

@Composable
private fun Unlocked(
    pendingLink: MutableStateFlow<String?>,
    model: RootViewModel,
) {
    val nav = rememberNavController()
    val link by pendingLink.collectAsState()
    val firstRun by model.firstRun.collectAsState()
    LaunchedEffect(firstRun) {
        val choice = firstRun ?: return@LaunchedEffect
        model.firstRunShown()
        when (choice) {
            FirstRun.SIGN_UP -> {
                nav.navigate("signup")
            }

            FirstRun.LOG_IN -> {
                nav.navigate("login")
            }

            FirstRun.ADVANCED -> {
                nav.navigate("sync?link=")
            }

            FirstRun.OFFLINE -> {}
        }
    }
    LaunchedEffect(link) {
        val l = link ?: return@LaunchedEffect
        pendingLink.value = null
        when {
            l.startsWith("otpauth", ignoreCase = true) -> nav.navigate("add?link=${android.net.Uri.encode(l)}&mode=MANUAL")
            l.startsWith("uotp://", ignoreCase = true) -> nav.navigate("sync?link=${android.net.Uri.encode(l)}")
        }
    }
    NavHost(
        navController = nav,
        startDestination = "codes",
        enterTransition = { slideInHorizontally(animationSpec = tween(NAV_MS), initialOffsetX = { it / 6 }) + fadeIn(tween(NAV_MS)) },
        exitTransition = { fadeOut(tween(NAV_MS / 2)) },
        popEnterTransition = { fadeIn(tween(NAV_MS)) },
        popExitTransition = { slideOutHorizontally(animationSpec = tween(NAV_MS), targetOffsetX = { it / 6 }) + fadeOut(tween(NAV_MS)) },
    ) {
        composable("codes") {
            CodesScreen(
                onAdd = { mode -> nav.navigate("add?link=&mode=${mode.name}") },
                onEdit = { id -> nav.navigate("edit/$id") },
                onSettings = { nav.navigate("settings") },
                onSync = { nav.navigate("sync?link=") },
                onTrash = { nav.navigate("trash") },
            )
        }
        composable(
            "add?link={link}&mode={mode}",
            arguments =
                listOf(
                    navArgument("link") {
                        type = NavType.StringType
                        defaultValue = ""
                    },
                    navArgument("mode") {
                        type = NavType.StringType
                        defaultValue = AddMode.SCAN.name
                    },
                ),
        ) {
            AddScreen(
                initialLink = it.arguments?.getString("link").orEmpty(),
                initialMode = AddMode.entries.firstOrNull { m -> m.name == it.arguments?.getString("mode") } ?: AddMode.SCAN,
                onDone = { nav.popBackStack() },
                onSyncLink = { l -> nav.navigate("sync?link=${android.net.Uri.encode(l)}") },
            )
        }
        composable("edit/{id}") { EditScreen(id = it.arguments?.getString("id").orEmpty(), onDone = { nav.popBackStack() }) }
        composable("settings") {
            SettingsScreen(
                onBack = { nav.popBackStack() },
                onSync = { nav.navigate("sync?link=") },
                onSessions = { nav.navigate("sessions") },
                onTrash = { nav.navigate("trash") },
                onAccount = { nav.navigate("account") },
                onAutofillAssociations = { nav.navigate("autofill-associations") },
            )
        }
        composable("trash") { TrashScreen(onBack = { nav.popBackStack() }) }
        composable("account") { AccountScreen(onBack = { nav.popBackStack() }) }
        composable("autofill-associations") { AutofillAssociationsScreen(onBack = { nav.popBackStack() }) }
        composable("sessions") { SessionsScreen(onBack = { nav.popBackStack() }) }
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
                onSignup = { nav.navigate("signup") },
                onSessions = { nav.navigate("sessions") },
            )
        }
        composable("login") { LoginScreen(defaultServer = "", label = deviceLabel(), onBack = { nav.popBackStack() }) }
        composable("signup") {
            SignupScreen(
                defaultServer = "",
                label = deviceLabel(),
                onBack = { nav.popBackStack() },
                onLogin = {
                    nav.popBackStack()
                    nav.navigate("login")
                },
            )
        }
    }
}
