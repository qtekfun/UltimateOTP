// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.fake

import com.qtekfun.ultimateotp.core.crypto.B64u
import com.qtekfun.ultimateotp.core.crypto.Ed25519
import com.qtekfun.ultimateotp.core.crypto.SrpGroup
import com.qtekfun.ultimateotp.core.crypto.Statements
import com.qtekfun.ultimateotp.core.sync.api.Accepted
import com.qtekfun.ultimateotp.core.sync.api.AccountKeys
import com.qtekfun.ultimateotp.core.sync.api.ApproveRequest
import com.qtekfun.ultimateotp.core.sync.api.Approver
import com.qtekfun.ultimateotp.core.sync.api.CommitRequest
import com.qtekfun.ultimateotp.core.sync.api.Device
import com.qtekfun.ultimateotp.core.sync.api.DeviceList
import com.qtekfun.ultimateotp.core.sync.api.EmailRequest
import com.qtekfun.ultimateotp.core.sync.api.EnrollRequest
import com.qtekfun.ultimateotp.core.sync.api.EnrollResponse
import com.qtekfun.ultimateotp.core.sync.api.EnrollmentToken
import com.qtekfun.ultimateotp.core.sync.api.Item
import com.qtekfun.ultimateotp.core.sync.api.JoinRequest
import com.qtekfun.ultimateotp.core.sync.api.JoinResponse
import com.qtekfun.ultimateotp.core.sync.api.KeyAttributes
import com.qtekfun.ultimateotp.core.sync.api.KeyBundleDto
import com.qtekfun.ultimateotp.core.sync.api.Pairing
import com.qtekfun.ultimateotp.core.sync.api.PairingCreated
import com.qtekfun.ultimateotp.core.sync.api.PairingDevice
import com.qtekfun.ultimateotp.core.sync.api.PairingResult
import com.qtekfun.ultimateotp.core.sync.api.Problem
import com.qtekfun.ultimateotp.core.sync.api.PutKeysRequest
import com.qtekfun.ultimateotp.core.sync.api.RecoveryKeys
import com.qtekfun.ultimateotp.core.sync.api.RotateRequest
import com.qtekfun.ultimateotp.core.sync.api.SealedVaultKeyDto
import com.qtekfun.ultimateotp.core.sync.api.ServerInfo
import com.qtekfun.ultimateotp.core.sync.api.SessionInfo
import com.qtekfun.ultimateotp.core.sync.api.SessionList
import com.qtekfun.ultimateotp.core.sync.api.SignupRequest
import com.qtekfun.ultimateotp.core.sync.api.SrpAttributes
import com.qtekfun.ultimateotp.core.sync.api.SrpLoginResponse
import com.qtekfun.ultimateotp.core.sync.api.SrpSession
import com.qtekfun.ultimateotp.core.sync.api.SrpSessionRequest
import com.qtekfun.ultimateotp.core.sync.api.SrpVerifyRequest
import com.qtekfun.ultimateotp.core.sync.api.VaultChanges
import com.qtekfun.ultimateotp.core.sync.api.VaultHead
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import java.math.BigInteger
import kotlin.math.abs

/**
 * An in-memory implementation of the `/otp/v1` contract (contracts/openapi.yaml 1.0.0) on
 * MockWebServer, for client tests: it verifies request, head, seal and certificate signatures
 * like the real server, enforces optimistic concurrency, and its [state] can be replaced to
 * simulate a restored backup or tampering. Single account; no rate limits or network policy
 * ([failNext] injects any problem, such as `rate_limited` or `account_locked`).
 *
 * Contract 1.1.0 sign-up: with [signupEnabled], `/login/email-code` also "emails" codes to new
 * addresses and `POST /otp/v1/signup` creates the account (code check, `email_taken`,
 * `signup_disabled`, `keys_required`, proof of possession with `X-UOTP-Device: pending`), in the
 * real server's order. [accountExists] false starts with no account at all (a fresh server);
 * true is an account made by `ultimateotp account-create` for [email], waiting for its bootstrap.
 */
@Suppress("TooManyFunctions", "LargeClass")
class FakeUotpServer(
    /** `UOTP_SIGNUP=enabled`. */
    @Volatile var signupEnabled: Boolean = false,
    accountExists: Boolean = true,
) : AutoCloseable {
    private val json =
        Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            encodeDefaults = true
        }
    private val web = MockWebServer()

    /** The server clock, Unix seconds. */
    var now: Long = System.currentTimeMillis() / MILLIS

    val accountId = "acc_" + "A".repeat(ID_CHARS)
    private var counter = 0
    private val tokens = mutableMapOf<String, Int>()
    private var bundle: KeyBundleDto? = null
    private var keyEpoch = 1L
    private var keysRevision = 0L
    private var devicesRevision = 0L
    private val devices = linkedMapOf<String, Device>()
    private val sealedKeys = mutableMapOf<Pair<String, Long>, SealedVaultKeyDto>()
    private val pairings = mutableMapOf<String, PairingState>()
    private val nonces = mutableSetOf<String>()
    private var rotationRequired = false

    private var accountEmail: String? = if (accountExists) DEFAULT_EMAIL else null

    /** The account's address (contract 1.1.0: the account identifier). */
    val email: String get() = accountEmail ?: DEFAULT_EMAIL

    /** True once an account exists (made by the CLI or by sign-up). */
    val hasAccount: Boolean get() = accountEmail != null

    /** The last code "emailed" (tests read it from here). */
    var lastEmailCode: String? = null
        private set

    private class Code(
        val code: String,
        var attempts: Int = 0,
    )

    private val codes = mutableMapOf<String, Code>()
    private val injected = mutableMapOf<String, ArrayDeque<Problem>>()
    private val hits = mutableMapOf<String, Int>()

    /** The code "emailed" to [address] that is still valid, if any. */
    fun codeFor(address: String): String? = codes[address]?.code

    /** How many requests reached [path] (for example `/otp/v1/signup`). */
    fun requests(path: String): Int = hits[path] ?: 0

    /** The next request to [path] fails with this problem, whatever it carries. */
    fun failNext(
        path: String,
        status: Int,
        code: String,
        retryAfter: Long? = null,
    ) {
        injected.getOrPut(path) { ArrayDeque() }.addLast(Problem(status = status, code = code, retryAfter = retryAfter))
    }

    private val srpSessions = mutableMapOf<String, Triple<BigInteger, BigInteger, BigInteger>>() // id -> (A, b, B)

    /** The vault: head and items. */
    data class State(
        val head: VaultHead,
        val items: Map<String, Item>,
    )

    @Volatile var state = State(head(0, null, null), emptyMap())

    private class PairingState(
        val creator: String,
        val secret: String,
        var status: String,
    ) {
        var joiner: PairingDevice? = null
        var signature: String? = null
    }

    val url: String get() = web.url("/").toString().trimEnd('/')

    val bundleOrNull: KeyBundleDto? get() = bundle

    init {
        web.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = synchronized(this@FakeUotpServer) { handle(request) }
            }
        web.start()
    }

    override fun close() = web.close()

    /** An enrollment token, as `ultimateotp account-create` or an existing device mints. */
    fun issueToken(): String {
        val t = "uoe_" + "t${++counter}".padEnd(TOKEN_CHARS, 'x')
        tokens[t] = MAX_RECOVERY_FETCHES
        return t
    }

    private fun nextId(prefix: String) = prefix + (++counter).toString().padStart(ID_CHARS, '0')

    private fun head(
        version: Long,
        signedBy: String?,
        signature: String?,
    ) = VaultHead(accountId, version, keyEpoch, signedBy, signature, now, rotationRequired, devicesRevision)

    // ---- dispatch -----------------------------------------------------------------------------

    private class Fail(
        val status: Int,
        val problem: Problem,
    ) : Exception()

    private fun fail(
        status: Int,
        code: String,
        head: VaultHead? = null,
    ): Nothing =
        throw Fail(status, Problem(status = status, code = code, head = head, serverTime = if (code == "stale_request") now else null))

    private fun handle(request: RecordedRequest): MockResponse =
        try {
            route(request)
        } catch (f: Fail) {
            MockResponse
                .Builder()
                .code(f.status)
                .addHeader("Content-Type", "application/problem+json")
                .body(json.encodeToString(Problem.serializer(), f.problem))
                .build()
        }

    private fun <T> ok(
        serializer: KSerializer<T>,
        value: T,
        code: Int = OK,
    ): MockResponse =
        MockResponse
            .Builder()
            .code(code)
            .addHeader("Content-Type", "application/json")
            .body(json.encodeToString(serializer, value))
            .build()

    private fun <T> body(
        request: RecordedRequest,
        serializer: KSerializer<T>,
    ): T = runCatching { json.decodeFromString(serializer, request.body?.utf8().orEmpty()) }.getOrElse { fail(BAD, "invalid_request") }

    @Suppress("CyclomaticComplexMethod")
    private fun route(r: RecordedRequest): MockResponse {
        val path = r.url.encodedPath
        hits[path] = (hits[path] ?: 0) + 1
        injected[path]?.removeFirstOrNull()?.let { throw Fail(it.status, it) }
        val s = path.removePrefix("/otp/v1/").split('/')
        return when {
            path == "/otp/v1/server-info" -> {
                ok(ServerInfo.serializer(), ServerInfo("1.0.0", now))
            }

            path == "/otp/v1/enroll" -> {
                enroll(r)
            }

            path == "/otp/v1/recovery/keys" -> {
                recoveryKeys(r)
            }

            path == "/otp/v1/enrollment-tokens" -> {
                device(r)
                ok(EnrollmentToken.serializer(), EnrollmentToken(issueToken(), now + TEN_MIN), CREATED)
            }

            path == "/otp/v1/account/keys" && r.method == "PUT" -> {
                putKeys(r)
            }

            path == "/otp/v1/account/keys" -> {
                accountKeys(r)
            }

            path == "/otp/v1/srp/attributes" -> {
                srpAttributes(r)
            }

            path == "/otp/v1/login/email-code" -> {
                emailCode(body(r, EmailRequest.serializer()).email)
                ok(Accepted.serializer(), Accepted(), ACCEPTED)
            }

            path == "/otp/v1/signup" -> {
                signup(r)
            }

            path == "/otp/v1/srp/session" -> {
                srpSession(r)
            }

            path == "/otp/v1/srp/verify" -> {
                srpVerify(r)
            }

            path == "/otp/v1/sessions" -> {
                sessions(r)
            }

            path == "/otp/v1/devices" -> {
                device(r)
                ok(DeviceList.serializer(), DeviceList(devicesRevision, devices.values.toList()))
            }

            s.size == 3 && s[0] == "devices" && s[2] == "revoke" -> {
                revoke(r, s[1])
            }

            path == "/otp/v1/pairings" -> {
                createPairing(r)
            }

            s.size == 2 && s[0] == "pairings" -> {
                device(r)
                pairingView(s[1])
            }

            s.size == 3 && s[0] == "pairings" && s[2] == "join" -> {
                join(r, s[1])
            }

            s.size == 3 && s[0] == "pairings" && s[2] == "approve" -> {
                approve(r, s[1])
            }

            s.size == 3 && s[0] == "pairings" && s[2] == "reject" -> {
                device(r)
                (pairings[s[1]] ?: fail(NOT_FOUND, "not_found")).status = "rejected"
                pairingView(s[1])
            }

            s.size == 3 && s[0] == "pairings" && s[2] == "result" -> {
                result(r, s[1])
            }

            path == "/otp/v1/vault" -> {
                vault(r)
            }

            path == "/otp/v1/vault/commit" -> {
                commit(r)
            }

            path == "/otp/v1/vault/rotate" -> {
                rotate(r)
            }

            path == "/otp/v1/events" -> {
                events(r)
            }

            else -> {
                fail(NOT_FOUND, "not_found")
            }
        }
    }

    private fun events(r: RecordedRequest): MockResponse {
        device(r)
        val hello =
            "{\"version\":${state.head.version},\"key_epoch\":$keyEpoch,\"devices_revision\":$devicesRevision," +
                "\"rotation_required\":$rotationRequired}"
        val vault = "{\"version\":${state.head.version},\"key_epoch\":$keyEpoch,\"signed_by\":\"${state.head.signedBy}\"}"
        return MockResponse
            .Builder()
            .addHeader("Content-Type", "text/event-stream")
            .body("retry: 5000\n\nevent: hello\ndata: $hello\n\n: keepalive\n\nevent: vault\nid: ${state.head.version}\ndata: $vault\n\n")
            .build()
    }

    // ---- authentication -----------------------------------------------------------------------

    private fun checkSignature(
        r: RecordedRequest,
        publicKey: String,
    ) {
        val ts = r.headers["X-UOTP-Timestamp"]?.toLongOrNull() ?: fail(UNAUTHORIZED, "invalid_signature")
        if (abs(ts - now) > SKEW) fail(UNAUTHORIZED, "stale_request")
        val nonce = r.headers["X-UOTP-Nonce"] ?: fail(UNAUTHORIZED, "invalid_signature")
        val device = r.headers["X-UOTP-Device"] ?: fail(UNAUTHORIZED, "invalid_signature")
        val message = Statements.request(r.method, r.target, device, ts, nonce, r.body?.toByteArray() ?: ByteArray(0))
        if (!Ed25519.verifyB64u(publicKey, message, r.headers["X-UOTP-Signature"].orEmpty())) fail(UNAUTHORIZED, "invalid_signature")
        if (!nonces.add("$device/$nonce")) fail(UNAUTHORIZED, "replayed_request")
    }

    private fun device(r: RecordedRequest): Device {
        val d = devices[r.headers["X-UOTP-Device"]] ?: fail(UNAUTHORIZED, "invalid_signature")
        checkSignature(r, d.ed25519)
        if (d.revokedAt != null) fail(UNAUTHORIZED, "device_revoked")
        return d
    }

    private fun bearer(r: RecordedRequest): String =
        r.headers["Authorization"]?.removePrefix("Bearer ") ?: fail(UNAUTHORIZED, "invalid_token")

    // ---- enrollment ---------------------------------------------------------------------------

    private fun enroll(r: RecordedRequest): MockResponse {
        if (tokens.remove(bearer(r)) == null) fail(UNAUTHORIZED, "invalid_token")
        val req = body(r, EnrollRequest.serializer())
        checkSignature(r, req.ed25519)
        val via =
            if (bundle == null) {
                bundle = req.keys ?: fail(BAD, "keys_required")
                keysRevision = 1
                "bootstrap"
            } else {
                if (req.keys != null) fail(CONFLICT, "keys_exist")
                "token"
            }
        val d = Device(nextId("dev_"), req.label, req.ed25519, req.x25519, via, null, null, now, null, null)
        devices[d.deviceId] = d
        devicesRevision++
        return ok(EnrollResponse.serializer(), EnrollResponse(accountId, d, state.head), CREATED)
    }

    private fun recoveryKeys(r: RecordedRequest): MockResponse {
        val token = bearer(r)
        val left = tokens[token] ?: fail(UNAUTHORIZED, "invalid_token")
        if (left <= 0) fail(TOO_MANY, "rate_limited")
        tokens[token] = left - 1
        val b = bundle ?: fail(NOT_FOUND, "not_found")
        return ok(RecoveryKeys.serializer(), RecoveryKeys(accountId, keyEpoch, keysRevision, b.passwordWrap, b.passwordKdf, b.recoveryWrap))
    }

    private fun accountKeys(r: RecordedRequest): MockResponse {
        val d = device(r)
        val b = bundle ?: fail(NOT_FOUND, "not_found")
        val mine = sealedKeys[d.deviceId to keyEpoch]
        return ok(
            AccountKeys.serializer(),
            AccountKeys(accountId, keyEpoch, keysRevision, b.passwordWrap, b.passwordKdf, b.recoveryWrap, mine),
        )
    }

    private fun sessions(r: RecordedRequest): MockResponse {
        val me = device(r)
        val list =
            devices.values.map {
                SessionInfo(
                    it.deviceId,
                    it.label,
                    it.appVersion,
                    it.enrolledVia,
                    it.createdAt,
                    now,
                    "192.0.2.1",
                    it.revokedAt,
                    it.deviceId == me.deviceId,
                )
            }
        return ok(SessionList.serializer(), SessionList(list))
    }

    private fun putKeys(r: RecordedRequest): MockResponse {
        device(r)
        val req = body(r, PutKeysRequest.serializer())
        if (req.baseRevision != keysRevision) fail(CONFLICT, "keys_revision_conflict")
        if (req.keyEpoch != keyEpoch) fail(CONFLICT, "key_epoch_conflict")
        val previous = bundle
        val srp = if (req.passwordWrap == null) null else req.srp ?: previous?.srp
        bundle = KeyBundleDto(req.passwordWrap, req.passwordKdf, req.recoveryWrap, srp)
        keysRevision++
        return ok(
            AccountKeys.serializer(),
            AccountKeys(accountId, keyEpoch, keysRevision, req.passwordWrap, req.passwordKdf, req.recoveryWrap, null),
        )
    }

    private fun revoke(
        r: RecordedRequest,
        id: String,
    ): MockResponse {
        device(r)
        val d = devices[id] ?: fail(NOT_FOUND, "not_found")
        val revoked = d.copy(revokedAt = d.revokedAt ?: now)
        devices[id] = revoked
        sealedKeys.keys.removeAll { it.first == id }
        rotationRequired = true
        devicesRevision++
        return ok(Device.serializer(), revoked)
    }

    // ---- pairing ------------------------------------------------------------------------------

    private fun createPairing(r: RecordedRequest): MockResponse {
        val d = device(r)
        val id = nextId("pair_")
        val secret = "uop_" + "s${++counter}".padEnd(TOKEN_CHARS, 'y')
        pairings[id] = PairingState(d.deviceId, secret, "open")
        return ok(PairingCreated.serializer(), PairingCreated(id, secret, now + TEN_MIN), CREATED)
    }

    private fun pairingView(id: String): MockResponse {
        val p = pairings[id] ?: fail(NOT_FOUND, "not_found")
        return ok(Pairing.serializer(), Pairing(id, p.status, now + TEN_MIN, p.joiner))
    }

    private fun join(
        r: RecordedRequest,
        id: String,
    ): MockResponse {
        val p = pairings[id] ?: fail(NOT_FOUND, "not_found")
        if (bearer(r) != p.secret) fail(UNAUTHORIZED, "invalid_token")
        if (p.status != "open") fail(CONFLICT, "pairing_state")
        val req = body(r, JoinRequest.serializer())
        checkSignature(r, req.ed25519)
        val joiner = PairingDevice(nextId("dev_"), req.label, req.ed25519, req.x25519)
        p.joiner = joiner
        p.status = "joined"
        return ok(JoinResponse.serializer(), JoinResponse(id, joiner.deviceId, "joined"))
    }

    private fun approve(
        r: RecordedRequest,
        id: String,
    ): MockResponse {
        val approver = device(r)
        val p = pairings[id] ?: fail(NOT_FOUND, "not_found")
        val joiner = p.joiner ?: fail(CONFLICT, "pairing_state")
        val req = body(r, ApproveRequest.serializer())
        val cert = Statements.device(accountId, joiner.deviceId, joiner.ed25519, joiner.x25519)
        if (!Ed25519.verifyB64u(approver.ed25519, cert, req.deviceSignature)) fail(BAD, "invalid_device_signature")
        val seal = Statements.seal(accountId, keyEpoch, joiner.deviceId, B64u.decode(req.sealedVaultKey))
        if (!Ed25519.verifyB64u(approver.ed25519, seal, req.sealSignature)) fail(BAD, "invalid_seal_signature")
        val d =
            Device(
                joiner.deviceId,
                joiner.label,
                joiner.ed25519,
                joiner.x25519,
                "pairing",
                approver.deviceId,
                req.deviceSignature,
                now,
                null,
                null,
            )
        devices[d.deviceId] = d
        devicesRevision++
        sealedKeys[d.deviceId to keyEpoch] = SealedVaultKeyDto(keyEpoch, req.sealedVaultKey, approver.deviceId, req.sealSignature)
        p.status = "approved"
        p.signature = req.deviceSignature
        return ok(Device.serializer(), d)
    }

    private fun result(
        r: RecordedRequest,
        id: String,
    ): MockResponse {
        val p = pairings[id] ?: fail(NOT_FOUND, "not_found")
        if (bearer(r) != p.secret) fail(UNAUTHORIZED, "invalid_token")
        val joiner = p.joiner ?: fail(CONFLICT, "pairing_state")
        checkSignature(r, joiner.ed25519)
        val creator = devices.getValue(p.creator)
        val view =
            PairingResult(
                id,
                p.status,
                joiner.deviceId,
                accountId,
                Approver(creator.deviceId, creator.ed25519),
                p.signature,
                sealedKeys[joiner.deviceId to keyEpoch],
            )
        return ok(PairingResult.serializer(), view)
    }

    // ---- vault --------------------------------------------------------------------------------

    private fun vault(r: RecordedRequest): MockResponse {
        device(r)
        val since = r.url.queryParameter("since")?.toLongOrNull() ?: 0
        val s = state
        return ok(
            VaultChanges.serializer(),
            VaultChanges(
                s.head,
                s.items.values
                    .filter { it.version > since }
                    .sortedBy { it.version },
            ),
        )
    }

    private fun checkHead(
        signer: Device,
        version: Long,
        epoch: Long,
        signature: String,
        items: Map<String, Item>,
    ) {
        val manifest =
            Statements.manifest(
                items.values.filter { !it.deleted }.map { Statements.ManifestEntry(it.itemId, it.version, B64u.decode(it.blob!!)) },
            )
        if (!Ed25519.verifyB64u(signer.ed25519, Statements.head(accountId, version, epoch, signer.deviceId, manifest), signature)) {
            fail(BAD, "invalid_head_signature")
        }
    }

    private fun commit(r: RecordedRequest): MockResponse {
        val d = device(r)
        val req = body(r, CommitRequest.serializer())
        if (req.baseVersion != state.head.version) fail(CONFLICT, "version_conflict", state.head)
        if (req.keyEpoch != keyEpoch) fail(CONFLICT, "key_epoch_conflict", state.head)
        if (req.head.version != req.baseVersion + 1) fail(BAD, "bad_version")
        if (req.upserts.isEmpty() && req.deletes.isEmpty()) fail(BAD, "empty_commit")
        val v = req.head.version
        val items = state.items.toMutableMap()
        req.upserts.forEach { items[it.itemId] = Item(it.itemId, v, false, it.blob) }
        req.deletes.forEach { id ->
            if (id !in items) fail(BAD, "unknown_item")
            items[id] = Item(id, v, true, null)
        }
        checkHead(d, v, keyEpoch, req.head.signature, items)
        state = State(head(v, d.deviceId, req.head.signature), items)
        return ok(VaultHead.serializer(), state.head)
    }

    private fun rotate(r: RecordedRequest): MockResponse {
        val d = device(r)
        val req = body(r, RotateRequest.serializer())
        if (req.baseVersion != state.head.version) fail(CONFLICT, "version_conflict", state.head)
        if (req.newKeyEpoch != keyEpoch + 1) fail(CONFLICT, "key_epoch_conflict", state.head)
        val active =
            devices.values
                .filter { it.revokedAt == null }
                .map { it.deviceId }
                .toSet()
        if (req.deviceKeys.map { it.deviceId }.toSet() != active) fail(BAD, "incomplete_rotation")
        req.deviceKeys.forEach { k ->
            val msg = Statements.seal(accountId, req.newKeyEpoch, k.deviceId, B64u.decode(k.sealedVaultKey))
            if (!Ed25519.verifyB64u(d.ed25519, msg, k.sealSignature)) fail(BAD, "invalid_seal_signature")
        }
        val v = req.head.version
        val items = state.items.toMutableMap()
        req.upserts.forEach { items[it.itemId] = Item(it.itemId, v, false, it.blob) }
        req.deletes.forEach { id -> items[id] = Item(id, v, true, null) }
        if (items.values.any { !it.deleted && it.version != v }) fail(BAD, "incomplete_rotation")
        checkHead(d, v, req.newKeyEpoch, req.head.signature, items)
        keyEpoch = req.newKeyEpoch
        bundle = req.keys
        keysRevision++
        rotationRequired = false
        req.deviceKeys.forEach {
            sealedKeys[it.deviceId to keyEpoch] =
                SealedVaultKeyDto(keyEpoch, it.sealedVaultKey, d.deviceId, it.sealSignature)
        }
        state = State(head(v, d.deviceId, req.head.signature), items)
        return ok(VaultHead.serializer(), state.head)
    }

    // ---- SRP-6a server side (contract 1.1.0) -----------------------------------------------------

    private val group = SrpGroup.RFC5054_4096

    private fun srpAttributes(r: RecordedRequest): MockResponse {
        val req = body(r, EmailRequest.serializer())
        val srp = bundle?.srp
        val attrs =
            if (req.email == accountEmail && srp != null) {
                SrpAttributes(srp.srpUserId, srp.srpSalt, bundle?.passwordKdf.orEmpty(), emailCodeRequired = true)
            } else {
                // Decoy for unknown addresses: deterministic per address in the real server.
                SrpAttributes("00000000-0000-4000-8000-000000000000", B64u.encode(ByteArray(SALT)), bundle?.passwordKdf.orEmpty(), true)
            }
        return ok(SrpAttributes.serializer(), attrs)
    }

    private fun srpSession(r: RecordedRequest): MockResponse {
        val req = body(r, SrpSessionRequest.serializer())
        if (!checkCode(req.email, req.emailCode)) fail(UNAUTHORIZED, "invalid_email_code")
        val srp = bundle?.srp ?: fail(UNAUTHORIZED, "srp_failed")
        val v = BigInteger(1, B64u.decode(srp.srpVerifier))
        val b = BigInteger(1, ByteArray(EPHEMERAL).also { java.security.SecureRandom().nextBytes(it) })
        val bigB =
            group.k
                .multiply(v)
                .add(group.g.modPow(b, group.n))
                .mod(group.n)
        val id = "srp_" + "x${++counter}".padEnd(ID_CHARS, 'z')
        srpSessions[id] = Triple(BigInteger(1, B64u.decode(req.srpA)), b, bigB)
        return ok(SrpSession.serializer(), SrpSession(id, B64u.encode(group.pad(bigB))))
    }

    private fun srpVerify(r: RecordedRequest): MockResponse {
        val req = body(r, SrpVerifyRequest.serializer())
        checkSignature(r, req.device.ed25519)
        val (bigA, b, bigB) = srpSessions.remove(req.sessionId) ?: fail(UNAUTHORIZED, "srp_failed")
        val srp = bundle?.srp ?: fail(UNAUTHORIZED, "srp_failed")
        val v = BigInteger(1, B64u.decode(srp.srpVerifier))
        val u = group.hInt(group.pad(bigA), group.pad(bigB))
        val key = group.h(group.pad(bigA.multiply(v.modPow(u, group.n)).mod(group.n).modPow(b, group.n)))
        val hn = group.h(group.pad(group.n))
        val hg = group.h(group.pad(group.g))
        val xor = ByteArray(hn.size) { (hn[it].toInt() xor hg[it].toInt()).toByte() }
        val identity = srp.srpUserId.toByteArray()
        val m1 = group.h(xor, group.h(identity), B64u.decode(srp.srpSalt), group.pad(bigA), group.pad(bigB), key)
        if (!m1.contentEquals(B64u.decode(req.srpM1))) fail(UNAUTHORIZED, "srp_failed")
        val m2 = group.h(group.pad(bigA), m1, key)
        val d = Device(nextId("dev_"), req.device.label, req.device.ed25519, req.device.x25519, "password", null, null, now, null, null)
        devices[d.deviceId] = d
        devicesRevision++
        val bnd = bundle!!
        val keys = KeyAttributes(keyEpoch, keysRevision, bnd.passwordWrap, bnd.passwordKdf, bnd.recoveryWrap)
        return ok(SrpLoginResponse.serializer(), SrpLoginResponse(B64u.encode(m2), accountId, d, state.head, keys), CREATED)
    }

    // ---- emailed codes and sign-up (contract 1.1.0) ---------------------------------------------

    /** Like the server: codes go to the account's address, and to new ones only while sign-up is open. */
    private fun emailCode(address: String) {
        if (address != accountEmail && !signupEnabled) return
        val code = (100_000 + ++counter).toString()
        codes[address] = Code(code)
        lastEmailCode = code
    }

    /** Single use, at most [MAX_CODE_ATTEMPTS] wrong tries (expiry is not simulated). */
    private fun checkCode(
        address: String,
        code: String?,
    ): Boolean {
        val stored = codes[address]
        val usable = stored != null && code != null && stored.attempts < MAX_CODE_ATTEMPTS
        val right = usable && stored.code == code
        when {
            right -> {
                codes.remove(address)
                if (lastEmailCode == code) lastEmailCode = null
            }

            usable -> {
                stored.attempts++
            }
        }
        return right
    }

    private fun signup(r: RecordedRequest): MockResponse {
        if (!signupEnabled) fail(FORBIDDEN, "signup_disabled")
        val req = body(r, SignupRequest.serializer())
        if (req.keys.srp == null || req.keys.passwordWrap == null) fail(BAD, "keys_required")
        if (!checkCode(req.email, req.emailCode)) fail(UNAUTHORIZED, "invalid_email_code")
        if (accountEmail != null) {
            if (req.email == accountEmail) fail(CONFLICT, "email_taken")
            error("the fake server holds a single account")
        }
        // Proof of possession of the new device key, before anything is stored.
        if (r.headers["X-UOTP-Device"] != PENDING) fail(UNAUTHORIZED, "invalid_signature")
        checkSignature(r, req.device.ed25519)
        accountEmail = req.email
        bundle = req.keys
        keysRevision = 1
        val d =
            Device(nextId("dev_"), req.device.label, req.device.ed25519, req.device.x25519, "signup", null, null, now, null, null)
                .copy(appVersion = req.device.appVersion)
        devices[d.deviceId] = d
        devicesRevision++
        return ok(EnrollResponse.serializer(), EnrollResponse(accountId, d, state.head), CREATED)
    }

    private companion object {
        const val DEFAULT_EMAIL = "owner@example.com"
        const val PENDING = "pending"
        const val MAX_CODE_ATTEMPTS = 5
        const val FORBIDDEN = 403
        const val SALT = 16
        const val EPHEMERAL = 32
        const val ACCEPTED = 202
        const val MILLIS = 1000L
        const val ID_CHARS = 22
        const val TOKEN_CHARS = 43
        const val SKEW = 60L
        const val TEN_MIN = 600L
        const val MAX_RECOVERY_FETCHES = 5
        const val OK = 200
        const val CREATED = 201
        const val BAD = 400
        const val UNAUTHORIZED = 401
        const val NOT_FOUND = 404
        const val CONFLICT = 409
        const val TOO_MANY = 429
    }
}
