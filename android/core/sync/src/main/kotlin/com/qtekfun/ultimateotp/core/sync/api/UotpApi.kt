// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.api

import com.qtekfun.ultimateotp.core.crypto.B64u
import com.qtekfun.ultimateotp.core.crypto.DeviceKeys
import com.qtekfun.ultimateotp.core.crypto.Sodium
import com.qtekfun.ultimateotp.core.crypto.Statements
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException

/** A problem document from the server; branch on [code] (contract "Problem"). */
class ApiException(
    val status: Int,
    val problem: Problem,
) : IOException("HTTP $status ${problem.code}") {
    val code: String get() = problem.code
}

/** Who signs a request: a registered device, or a new device (`pending` / its pending id). */
class Signer(
    val keys: DeviceKeys,
    val deviceHeader: String,
)

/**
 * The `/otp/v1` client (contracts/openapi.yaml). Every request is signed with the device's
 * Ed25519 key over the contract's canonical request; the server's clock offset learned from
 * `stale_request` is applied to later timestamps.
 */
@Suppress("TooManyFunctions")
class UotpApi(
    baseUrl: String,
    private val http: OkHttpClient,
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / MILLIS },
    /** Sent as `X-UOTP-App-Version` (session metadata, decision 9); not signed. */
    val appVersion: String? = null,
) {
    private val base: HttpUrl = baseUrl.trimEnd('/').toHttpUrl()
    private val json =
        Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            encodeDefaults = true
        }

    /** Server clock minus local clock, seconds. */
    @Volatile var clockOffset: Long = 0

    val baseUrl: String get() = base.toString().trimEnd('/')

    fun url(pathAndQuery: String): HttpUrl {
        val path = pathAndQuery.substringBefore('?')
        val query = pathAndQuery.substringAfter('?', "")
        val builder = base.newBuilder()
        path.trim('/').split('/').forEach { builder.addPathSegment(it) }
        if (query.isNotEmpty()) builder.encodedQuery(query)
        return builder.build()
    }

    /** Builds a signed request (also used by the SSE stream). */
    fun request(
        method: String,
        pathAndQuery: String,
        body: ByteArray?,
        signer: Signer?,
        bearer: String?,
    ): Request {
        val url = url(pathAndQuery)
        val builder = Request.Builder().url(url)
        if (signer != null) {
            val timestamp = nowSeconds() + clockOffset
            val nonce = B64u.encode(Sodium.random(NONCE_BYTES))
            val target = url.encodedPath + (url.encodedQuery?.let { "?$it" } ?: "")
            val message = Statements.request(method, target, signer.deviceHeader, timestamp, nonce, body ?: ByteArray(0))
            builder
                .header("X-UOTP-Device", signer.deviceHeader)
                .header("X-UOTP-Timestamp", timestamp.toString())
                .header("X-UOTP-Nonce", nonce)
                .header("X-UOTP-Signature", signer.keys.signB64u(message))
        }
        if (bearer != null) builder.header("Authorization", "Bearer $bearer")
        if (signer != null && appVersion != null) builder.header("X-UOTP-App-Version", appVersion)
        val requestBody = body?.toRequestBody(JSON_TYPE)
        return builder
            .method(
                method,
                requestBody ?: if (method == "POST" || method == "PUT") ByteArray(0).toRequestBody(JSON_TYPE) else null,
            ).build()
    }

    private suspend fun <T> call(
        method: String,
        path: String,
        body: ByteArray?,
        signer: Signer?,
        bearer: String?,
        out: KSerializer<T>,
        retryOnSkew: Boolean = true,
    ): T {
        val response = withContext(Dispatchers.IO) { http.newCall(request(method, path, body, signer, bearer)).execute() }
        val text = response.use { readBody(it) }
        if (response.isSuccessful) {
            return try {
                json.decodeFromString(out, text)
            } catch (e: SerializationException) {
                throw IOException("unexpected response", e)
            }
        }
        val problem = runCatching { json.decodeFromString(Problem.serializer(), text) }.getOrElse { Problem(status = response.code) }
        val serverTime = problem.serverTime
        val skewed = problem.code == STALE && serverTime != null
        if (skewed && retryOnSkew && signer != null) {
            clockOffset = serverTime - nowSeconds()
            return call(method, path, body, signer, bearer, out, retryOnSkew = false)
        }
        throw ApiException(response.code, problem)
    }

    private fun readBody(response: Response): String = response.body.string()

    private inline fun <reified B> encode(
        serializer: KSerializer<B>,
        value: B,
    ): ByteArray = json.encodeToString(serializer, value).toByteArray()

    // ---- endpoints --------------------------------------------------------------------------

    suspend fun serverInfo(): ServerInfo = call("GET", "/otp/v1/server-info", null, null, null, ServerInfo.serializer())

    suspend fun enroll(
        token: String,
        signer: Signer,
        request: EnrollRequest,
    ): EnrollResponse =
        call("POST", "/otp/v1/enroll", encode(EnrollRequest.serializer(), request), signer, token, EnrollResponse.serializer())

    suspend fun recoveryKeys(token: String): RecoveryKeys =
        call("GET", "/otp/v1/recovery/keys", null, null, token, RecoveryKeys.serializer())

    suspend fun createEnrollmentToken(signer: Signer): EnrollmentToken =
        call("POST", "/otp/v1/enrollment-tokens", null, signer, null, EnrollmentToken.serializer())

    suspend fun accountKeys(signer: Signer): AccountKeys = call("GET", "/otp/v1/account/keys", null, signer, null, AccountKeys.serializer())

    suspend fun putAccountKeys(
        signer: Signer,
        request: PutKeysRequest,
    ): AccountKeys =
        call("PUT", "/otp/v1/account/keys", encode(PutKeysRequest.serializer(), request), signer, null, AccountKeys.serializer())

    suspend fun devices(signer: Signer): DeviceList = call("GET", "/otp/v1/devices", null, signer, null, DeviceList.serializer())

    suspend fun revoke(
        signer: Signer,
        deviceId: String,
    ): Device = call("POST", "/otp/v1/devices/$deviceId/revoke", null, signer, null, Device.serializer())

    suspend fun createPairing(signer: Signer): PairingCreated =
        call("POST", "/otp/v1/pairings", null, signer, null, PairingCreated.serializer())

    suspend fun pairing(
        signer: Signer,
        id: String,
    ): Pairing = call("GET", "/otp/v1/pairings/$id", null, signer, null, Pairing.serializer())

    suspend fun join(
        secret: String,
        signer: Signer,
        id: String,
        request: JoinRequest,
    ): JoinResponse =
        call("POST", "/otp/v1/pairings/$id/join", encode(JoinRequest.serializer(), request), signer, secret, JoinResponse.serializer())

    suspend fun approve(
        signer: Signer,
        id: String,
        request: ApproveRequest,
    ): Device =
        call("POST", "/otp/v1/pairings/$id/approve", encode(ApproveRequest.serializer(), request), signer, null, Device.serializer())

    suspend fun reject(
        signer: Signer,
        id: String,
    ): Pairing = call("POST", "/otp/v1/pairings/$id/reject", null, signer, null, Pairing.serializer())

    suspend fun pairingResult(
        secret: String,
        signer: Signer,
        id: String,
    ): PairingResult = call("GET", "/otp/v1/pairings/$id/result", null, signer, secret, PairingResult.serializer())

    suspend fun vault(
        signer: Signer,
        since: Long,
    ): VaultChanges = call("GET", "/otp/v1/vault?since=$since", null, signer, null, VaultChanges.serializer())

    suspend fun commit(
        signer: Signer,
        request: CommitRequest,
    ): VaultHead = call("POST", "/otp/v1/vault/commit", encode(CommitRequest.serializer(), request), signer, null, VaultHead.serializer())

    suspend fun rotate(
        signer: Signer,
        request: RotateRequest,
    ): VaultHead = call("POST", "/otp/v1/vault/rotate", encode(RotateRequest.serializer(), request), signer, null, VaultHead.serializer())

    suspend fun requestEmailCode(email: String): Accepted =
        call("POST", "/otp/v1/login/email-code", encode(EmailRequest.serializer(), EmailRequest(email)), null, null, Accepted.serializer())

    suspend fun srpAttributes(email: String): SrpAttributes =
        call(
            "POST",
            "/otp/v1/srp/attributes",
            encode(EmailRequest.serializer(), EmailRequest(email)),
            null,
            null,
            SrpAttributes.serializer(),
        )

    suspend fun srpSession(request: SrpSessionRequest): SrpSession =
        call("POST", "/otp/v1/srp/session", encode(SrpSessionRequest.serializer(), request), null, null, SrpSession.serializer())

    suspend fun srpVerify(
        signer: Signer,
        request: SrpVerifyRequest,
    ): SrpLoginResponse =
        call("POST", "/otp/v1/srp/verify", encode(SrpVerifyRequest.serializer(), request), signer, null, SrpLoginResponse.serializer())

    suspend fun sessions(signer: Signer): SessionList = call("GET", "/otp/v1/sessions", null, signer, null, SessionList.serializer())

    companion object {
        const val PENDING = "pending"
        const val STALE = "stale_request"
        private const val NONCE_BYTES = 16
        private const val MILLIS = 1000L
        private val JSON_TYPE = "application/json".toMediaType()
    }
}
