// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.lock

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.vault.secure.AuthenticationRequiredException
import com.qtekfun.ultimateotp.ui.Authenticate
import com.qtekfun.ultimateotp.ui.FirstRun
import com.qtekfun.ultimateotp.ui.RootViewModel
import com.qtekfun.ultimateotp.ui.components.Callout
import com.qtekfun.ultimateotp.ui.components.CalloutKind
import com.qtekfun.ultimateotp.ui.components.IconBadge
import com.qtekfun.ultimateotp.ui.components.UotpLogo
import com.qtekfun.ultimateotp.ui.components.WidthClass
import com.qtekfun.ultimateotp.ui.components.currentWidthClass
import com.qtekfun.ultimateotp.ui.theme.Brand
import com.qtekfun.ultimateotp.ui.theme.Space
import kotlinx.coroutines.launch

/** First run, like Ente Auth's: create an account, log in, or stay offline; token/pairing is advanced. */
@Composable
fun WelcomeScreen(onChoice: (FirstRun) -> Unit) {
    WelcomeContent(onChoice = onChoice, widthClass = currentWidthClass())
}

@Composable
fun WelcomeContent(
    onChoice: (FirstRun) -> Unit,
    widthClass: WidthClass,
    modifier: Modifier = Modifier,
) {
    Surface(modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Box(Modifier.fillMaxSize().safeDrawingPadding(), contentAlignment = Alignment.Center) {
            if (widthClass == WidthClass.COMPACT) {
                Column(
                    Modifier
                        .widthIn(
                            max = 520.dp,
                        ).verticalScroll(rememberScrollState())
                        .padding(horizontal = Space.Xl, vertical = Space.Lg),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(Space.Xl),
                ) {
                    Hero()
                    ValuePoints()
                    Choices(onChoice)
                }
            } else {
                Row(
                    Modifier.widthIn(max = 1040.dp).verticalScroll(rememberScrollState()).padding(Space.Xxl),
                    horizontalArrangement = Arrangement.spacedBy(Space.Huge),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(
                        Modifier.weight(1f),
                        horizontalAlignment = Alignment.Start,
                        verticalArrangement = Arrangement.spacedBy(Space.Xl),
                    ) {
                        Hero()
                        ValuePoints()
                    }
                    Column(Modifier.weight(0.8f)) { Choices(onChoice) }
                }
            }
        }
    }
}

@Composable
private fun Hero() {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(Space.Lg)) {
        Box(contentAlignment = Alignment.Center) {
            Box(
                Modifier
                    .size(180.dp)
                    .clip(CircleShape)
                    .background(Brush.radialGradient(listOf(Brand.Emerald.copy(alpha = 0.32f), Color.Transparent))),
            )
            UotpLogo(size = 96.dp)
        }
        Text(
            stringResource(R.string.welcome_title),
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(R.string.welcome_body),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ValuePoints() {
    Column(verticalArrangement = Arrangement.spacedBy(Space.Lg)) {
        ValuePoint(Icons.Filled.WifiOff, R.string.value_offline_title, R.string.value_offline_body)
        ValuePoint(Icons.Filled.CloudSync, R.string.value_sync_title, R.string.value_sync_body)
        ValuePoint(Icons.Filled.Dns, R.string.value_server_title, R.string.value_server_body)
    }
}

@Composable
private fun ValuePoint(
    icon: ImageVector,
    title: Int,
    body: Int,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(Space.Lg), verticalAlignment = Alignment.Top) {
        IconBadge(icon, size = 44.dp)
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(body), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Choices(onChoice: (FirstRun) -> Unit) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Space.Md),
    ) {
        Button(
            onClick = { onChoice(FirstRun.SIGN_UP) },
            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
            shape = MaterialTheme.shapes.large,
        ) { Text(stringResource(R.string.welcome_signup), style = MaterialTheme.typography.titleMedium) }
        FilledTonalButton(
            onClick = { onChoice(FirstRun.LOG_IN) },
            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
            shape = MaterialTheme.shapes.large,
        ) { Text(stringResource(R.string.welcome_login), style = MaterialTheme.typography.titleMedium) }
        TextButton(onClick = { onChoice(FirstRun.OFFLINE) }, modifier = Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(R.string.welcome_offline))
        }
        TextButton(onClick = { onChoice(FirstRun.ADVANCED) }, modifier = Modifier.heightIn(min = 48.dp)) {
            Text(
                stringResource(R.string.welcome_advanced),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
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
    LockContent(error = error, onUnlock = unlock)
}

@Composable
fun LockContent(
    error: String?,
    onUnlock: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Box(Modifier.fillMaxSize().safeDrawingPadding(), contentAlignment = Alignment.Center) {
            Column(
                Modifier.widthIn(max = 420.dp).verticalScroll(rememberScrollState()).padding(Space.Xl),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(Space.Lg),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Box(
                        Modifier
                            .size(200.dp)
                            .clip(CircleShape)
                            .background(Brush.radialGradient(listOf(Brand.Mint.copy(alpha = 0.22f), Color.Transparent))),
                    )
                    UotpLogo(size = 96.dp)
                }
                Text(
                    stringResource(R.string.locked_title),
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.semantics { heading() },
                )
                Text(
                    stringResource(R.string.locked_body),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                error?.let { Callout(it, kind = CalloutKind.ERROR) }
                Button(
                    onClick = onUnlock,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                    shape = MaterialTheme.shapes.large,
                ) {
                    Icon(Icons.Filled.Fingerprint, contentDescription = null)
                    Text(stringResource(R.string.unlock), modifier = Modifier.padding(start = Space.Sm))
                }
            }
        }
    }
}
