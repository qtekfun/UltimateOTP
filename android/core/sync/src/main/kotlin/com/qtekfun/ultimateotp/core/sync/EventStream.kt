// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync

import com.qtekfun.ultimateotp.core.sync.api.Signer
import com.qtekfun.ultimateotp.core.sync.api.UotpApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/** One server-sent event (docs/sync.md): a notification, never data. */
data class ServerEvent(
    val type: String,
    val data: String,
)

/**
 * The live-sync listener: `GET /otp/v1/events` signed like any request, reconnecting with
 * backoff (5 s, doubling up to 60 s, with jitter). The server closes a stream after an hour; a
 * new one gets a fresh signature. Stops for good on a `revoked` event.
 */
class EventStream(
    private val http: OkHttpClient,
    private val api: () -> UotpApi?,
    private val signer: () -> Signer?,
    private val onEvent: suspend (ServerEvent) -> Unit,
) {
    private var job: Job? = null

    fun start(scope: CoroutineScope) {
        if (job?.isActive == true) return
        job = scope.launch(Dispatchers.IO) { loop() }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    @Suppress("NestedBlockDepth") // One reconnect loop around one blocking read.
    private suspend fun CoroutineScope.loop() {
        val client = http.newBuilder().readTimeout(0, TimeUnit.MILLISECONDS).build()
        var backoff = MIN_BACKOFF_MS
        while (isActive) {
            val api = api()
            val signer = signer()
            if (api == null || signer == null) return
            val revoked =
                try {
                    client.newCall(api.request("GET", "/otp/v1/events", null, signer, null)).execute().use { response ->
                        if (!response.isSuccessful) throw IOException("HTTP ${response.code}")
                        backoff = MIN_BACKOFF_MS
                        read(response.body.source())
                    }
                } catch (_: IOException) {
                    false
                }
            if (revoked) return
            delay(backoff + Random.nextLong(backoff / 2))
            backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
    }

    /** Parses `event:`/`data:` lines until the stream ends. @return true after `revoked`. */
    @Suppress("NestedBlockDepth") // The SSE line grammar, in one place.
    private suspend fun read(source: okio.BufferedSource): Boolean {
        var type = "message"
        val data = StringBuilder()
        while (true) {
            val line = source.readUtf8Line() ?: return false
            when {
                line.isEmpty() -> {
                    if (data.isNotEmpty() || type != "message") {
                        onEvent(ServerEvent(type, data.toString()))
                        if (type == "revoked") return true
                    }
                    type = "message"
                    data.clear()
                }

                line.startsWith(":") -> {
                    // A comment (keepalive).
                }

                line.startsWith("event:") -> {
                    type = line.substringAfter(':').trim()
                }

                line.startsWith("data:") -> {
                    data.append(line.substringAfter(':').trimStart())
                }
            }
        }
    }

    private companion object {
        const val MIN_BACKOFF_MS = 5_000L
        const val MAX_BACKOFF_MS = 60_000L
    }
}
