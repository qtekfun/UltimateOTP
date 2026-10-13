// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.lock

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import com.qtekfun.ultimateotp.ui.Authenticate
import com.qtekfun.ultimateotp.ui.RootViewModel
import kotlinx.coroutines.launch

@Composable
fun WelcomeScreen(onCreate: () -> Unit) {
    Centered {
        Icon(Icons.Default.Lock, contentDescription = null)
        Text(stringResource(R.string.welcome_title), style = MaterialTheme.typography.headlineSmall)
        Text(stringResource(R.string.welcome_body), textAlign = TextAlign.Center)
        Button(onClick = onCreate) { Text(stringResource(R.string.welcome_create)) }
    }
}

@Composable
fun LockScreen(
    authenticate: Authenticate,
    model: RootViewModel = hiltViewModel(),
) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    val unlock = {
        scope.launch {
            try {
                model.vault.unlock()
            } catch (_: AuthenticationRequiredException) {
                authenticate({ scope.launch { runCatching { model.vault.unlock() }.onFailure { error = it.message } } }, { error = it })
            }
        }
        Unit
    }
    LaunchedEffect(Unit) { unlock() }
    Centered {
        Icon(Icons.Default.Lock, contentDescription = null)
        Text(stringResource(R.string.locked_title), style = MaterialTheme.typography.headlineSmall)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(onClick = unlock) { Text(stringResource(R.string.unlock)) }
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.padding(32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(0.dp))
            content()
        }
    }
}
