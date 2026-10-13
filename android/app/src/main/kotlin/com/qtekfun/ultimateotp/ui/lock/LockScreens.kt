// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.lock

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.ui.FirstRun
import com.qtekfun.ultimateotp.ui.RootViewModel

/** First run, like Ente Auth: create an account, log in, or stay offline; token/pairing is advanced. */
@Composable
fun WelcomeScreen(onChoice: (FirstRun) -> Unit) {
    Centered {
        Icon(Icons.Default.Lock, contentDescription = null)
        Text(stringResource(R.string.welcome_title), style = MaterialTheme.typography.headlineSmall)
        Text(stringResource(R.string.welcome_body), textAlign = TextAlign.Center)
        Button(onClick = { onChoice(FirstRun.SIGN_UP) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.welcome_signup))
        }
        OutlinedButton(onClick = { onChoice(FirstRun.LOG_IN) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.welcome_login))
        }
        TextButton(onClick = { onChoice(FirstRun.OFFLINE) }) { Text(stringResource(R.string.welcome_offline)) }
        TextButton(onClick = { onChoice(FirstRun.ADVANCED) }) {
            Text(stringResource(R.string.welcome_advanced), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
fun LockScreen(model: RootViewModel = hiltViewModel()) {
    LaunchedEffect(Unit) { model.unlock() }
    Centered {
        Icon(Icons.Default.Lock, contentDescription = null)
        Text(stringResource(R.string.locked_title), style = MaterialTheme.typography.headlineSmall)
        Button(onClick = model::unlock) { Text(stringResource(R.string.unlock)) }
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
