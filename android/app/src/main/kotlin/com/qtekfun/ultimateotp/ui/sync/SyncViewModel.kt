// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qtekfun.ultimateotp.auth.AuthGate
import com.qtekfun.ultimateotp.auth.GateResult
import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.sync.DeviceView
import com.qtekfun.ultimateotp.core.sync.EnrollLink
import com.qtekfun.ultimateotp.core.sync.EnrollmentPolicy
import com.qtekfun.ultimateotp.core.sync.HeadRejectedException
import com.qtekfun.ultimateotp.core.sync.JoinedPairing
import com.qtekfun.ultimateotp.core.sync.PairLink
import com.qtekfun.ultimateotp.core.sync.SyncResult
import com.qtekfun.ultimateotp.core.sync.api.ApiException
import com.qtekfun.ultimateotp.core.sync.api.PairingDevice
import com.qtekfun.ultimateotp.core.sync.api.SessionInfo
import com.qtekfun.ultimateotp.core.vault.VaultRepository
import com.qtekfun.ultimateotp.sync.SyncController
import com.qtekfun.ultimateotp.sync.SyncStatus
import com.qtekfun.ultimateotp.util.AppSettings
import com.qtekfun.ultimateotp.util.Settings
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
import javax.inject.Inject

/** One step of the sync screen's flows. */
sealed interface SyncStep {
    data object Idle : SyncStep

    data class Busy(
        val what: Busy.Kind,
    ) : SyncStep {
        enum class Kind { WORKING, DERIVING_KEY }
    }

    /** Shown once after the account was created. */
    data class RecoveryWords(
        val words: List<String>,
    ) : SyncStep

    /** Existing device: QR shown, waiting for the new device to join. */
    data class PairQr(
        val link: PairLink,
    ) : SyncStep

    /** Existing device: compare these words with the new device's screen. */
    data class ConfirmPairing(
        val pairingId: String,
        val device: PairingDevice,
        val words: List<String>,
    ) : SyncStep

    /** New device: these words must match the other screen; waiting for approval. */
    data class JoinWaiting(
        val words: List<String>,
    ) : SyncStep

    data class Failed(
        val reason: Reason,
    ) : SyncStep

    data class Done(
        val what: DoneKind,
    ) : SyncStep

    enum class Reason { NETWORK, WRONG_SECRET, LAN_ONLY, REJECTED_STATE, REFUSED, SERVER, LOGIN_UNAVAILABLE, UNEXPECTED }

    enum class DoneKind { ENROLLED, PAIRED, PAIRING_DECLINED, ROTATED, UPLOADED, PASSWORD_CHANGED }
}

@HiltViewModel
class SyncViewModel
    @Inject
    constructor(
        private val controller: SyncController,
        private val vault: VaultRepository,
        private val appSettings: AppSettings,
        private val gate: AuthGate,
    ) : ViewModel() {
        val status: StateFlow<SyncStatus> = controller.status
        val settings: StateFlow<Settings> = appSettings.settings.stateIn(viewModelScope, SharingStarted.Eagerly, Settings())
        private val _step = MutableStateFlow<SyncStep>(SyncStep.Idle)
        val step: StateFlow<SyncStep> = _step.asStateFlow()
        private val _sessions = MutableStateFlow<Map<String, SessionInfo>>(emptyMap())
        val sessions: StateFlow<Map<String, SessionInfo>> = _sessions.asStateFlow()
        private val _devices = MutableStateFlow<List<DeviceView>>(emptyList())
        val devices: StateFlow<List<DeviceView>> = _devices.asStateFlow()
        private var poll: Job? = null

        private val engine get() = controller.engine

        fun reset() {
            poll?.cancel()
            _step.value = SyncStep.Idle
        }

        fun saveServer(
            serverUrl: String,
            enrollmentUrl: String,
            allowRemote: Boolean,
        ) = viewModelScope.launch {
            gate.attempt {
                appSettings.update {
                    it.copy(
                        serverUrl = serverUrl.trim(),
                        enrollmentUrl = enrollmentUrl.trim(),
                        allowRemoteEnrollment = allowRemote,
                    )
                }
            }
        }

        /** A `uotp://` link scanned or opened: pairing (join) or an enrollment token. */
        fun handleLink(
            link: String,
            label: String,
            onEnrollLink: (EnrollLink) -> Unit,
        ) {
            PairLink.parse(link)?.let { return join(it, label) }
            EnrollLink.parse(link)?.let(onEnrollLink)
        }

        /**
         * Runs [block] behind the [AuthGate] (the operations here write Keystore secrets, and the
         * engine checks the Keystore before any request that changes the server). Declining the
         * prompt returns to the step the screen was on; the gate has told the person why.
         */
        private fun run(
            kind: SyncStep.Busy.Kind = SyncStep.Busy.Kind.WORKING,
            block: suspend () -> SyncStep,
        ) {
            viewModelScope.launch {
                val before = _step.value
                _step.value = SyncStep.Busy(kind)
                _step.value =
                    attempt {
                        when (val r = gate.run(block)) {
                            is GateResult.Done -> r.value
                            else -> before.takeUnless { it is SyncStep.Busy } ?: SyncStep.Idle
                        }
                    }
                runRefresh()
            }
        }

        private suspend fun runRefresh() {
            try {
                controller.refresh()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // The step is already shown; a failed account re-read must not end the app.
            }
        }

        /** Maps every failure to a reason the UI can explain; never shows secrets or raw errors. */
        private suspend fun attempt(block: suspend () -> SyncStep): SyncStep =
            try {
                block()
            } catch (e: ApiException) {
                SyncStep.Failed(
                    when (e.code) {
                        "enrollment_network_denied" -> SyncStep.Reason.LAN_ONLY
                        "invalid_token", "pairing_expired", "pairing_state" -> SyncStep.Reason.REFUSED
                        else -> SyncStep.Reason.SERVER
                    },
                )
            } catch (_: IOException) {
                SyncStep.Failed(SyncStep.Reason.NETWORK)
            } catch (_: CryptoException) {
                SyncStep.Failed(SyncStep.Reason.WRONG_SECRET)
            } catch (_: HeadRejectedException) {
                SyncStep.Failed(SyncStep.Reason.REJECTED_STATE)
            } catch (_: IllegalArgumentException) {
                SyncStep.Failed(SyncStep.Reason.REFUSED)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // A bug or a full disk: shown as a failed step, never as a dead process.
                SyncStep.Failed(SyncStep.Reason.UNEXPECTED)
            }

        /** Enrollment and recovery go to the LAN address unless the owner allowed otherwise (decision 4). */
        private fun enrollmentUrl(server: String): String? {
            val s = settings.value
            return when (val c = EnrollmentPolicy.choose(server, s.enrollmentUrl, s.allowRemoteEnrollment)) {
                is EnrollmentPolicy.Choice.Use -> c.url
                EnrollmentPolicy.Choice.Refused -> null
            }
        }

        /** Points the account at the everyday server URL after enrolling through the LAN address. */
        private suspend fun useServer(server: String) {
            val account = vault.account() ?: return
            if (account.serverUrl != server) vault.apply(emptyList(), emptyList(), account.copy(serverUrl = server))
        }

        fun bootstrap(
            server: String,
            token: String,
            password: String?,
            label: String,
            emailCode: String,
        ) = run(SyncStep.Busy.Kind.DERIVING_KEY) {
            val url = enrollmentUrl(server) ?: return@run SyncStep.Failed(SyncStep.Reason.LAN_ONLY)
            val words = engine.bootstrap(url, token.trim(), password, label, emailCode.trim().ifBlank { null })
            useServer(server)
            controller.syncNow()
            SyncStep.RecoveryWords(words)
        }

        fun enrollWithPassword(
            server: String,
            token: String,
            password: String,
            label: String,
        ) = run(SyncStep.Busy.Kind.DERIVING_KEY) {
            val url = enrollmentUrl(server) ?: return@run SyncStep.Failed(SyncStep.Reason.LAN_ONLY)
            engine.enrollWithPassword(url, token.trim(), password, label)
            useServer(server)
            controller.syncNow()
            SyncStep.Done(SyncStep.DoneKind.ENROLLED)
        }

        fun enrollWithRecoveryKey(
            server: String,
            token: String,
            words: String,
            label: String,
        ) = run {
            val url = enrollmentUrl(server) ?: return@run SyncStep.Failed(SyncStep.Reason.LAN_ONLY)
            engine.enrollWithRecoveryKey(url, token.trim(), words, label)
            useServer(server)
            controller.syncNow()
            SyncStep.Done(SyncStep.DoneKind.ENROLLED)
        }

        /** Email + emailed code + SRP password login (decisions 6 and 13): waits for the contract. */
        fun loginUnavailable() {
            _step.value = SyncStep.Failed(SyncStep.Reason.LOGIN_UNAVAILABLE)
        }

        // ---- pairing ------------------------------------------------------------------------------

        fun startPairing() =
            run {
                val link = engine.startPairing()
                poll =
                    viewModelScope.launch {
                        var candidate: Pair<PairingDevice, List<String>>? = null
                        while (isActive && candidate == null) {
                            delay(POLL_MS)
                            candidate = runCatching { engine.pairingCandidate(link.pairingId) }.getOrNull()
                        }
                        candidate?.let { (device, words) -> _step.value = SyncStep.ConfirmPairing(link.pairingId, device, words) }
                    }
                SyncStep.PairQr(link)
            }

        fun approve(step: SyncStep.ConfirmPairing) =
            run {
                engine.approvePairing(step.pairingId, step.device)
                SyncStep.Done(SyncStep.DoneKind.PAIRED)
            }

        fun decline(step: SyncStep.ConfirmPairing) =
            run {
                engine.rejectPairing(step.pairingId)
                SyncStep.Done(SyncStep.DoneKind.PAIRING_DECLINED)
            }

        private fun join(
            link: PairLink,
            label: String,
        ) {
            viewModelScope.launch {
                _step.value = SyncStep.Busy(SyncStep.Busy.Kind.WORKING)
                var joined: JoinedPairing? = null
                val failed =
                    attempt {
                        // Saves this device's keys first thing, which may need the user to authenticate.
                        when (val r = gate.run { engine.joinPairing(link, label) }) {
                            is GateResult.Done -> joined = r.value
                            else -> Unit
                        }
                        SyncStep.Idle
                    }
                val pairing = joined
                if (pairing == null) {
                    _step.value = failed
                    return@launch
                }
                _step.value = SyncStep.JoinWaiting(pairing.sasWords)
                _step.value =
                    attempt {
                        // Adopting the key may need the user to authenticate after a long wait; the
                        // server's answer can be read again, so the wait is simply resumed.
                        when (val r = gate.run { engine.awaitPairing(pairing, label) }) {
                            is GateResult.Done -> {
                                if (r.value) {
                                    controller.syncNow()
                                    SyncStep.Done(SyncStep.DoneKind.PAIRED)
                                } else {
                                    SyncStep.Done(SyncStep.DoneKind.PAIRING_DECLINED)
                                }
                            }

                            else -> {
                                SyncStep.Idle
                            }
                        }
                    }
                runRefresh()
            }
        }

        // ---- account ------------------------------------------------------------------------------

        fun syncNow() = controller.syncNow()

        fun loadDevices() =
            viewModelScope.launch {
                _devices.value = runCatching { engine.devices() }.getOrDefault(_devices.value)
                _sessions.value = runCatching { engine.sessions().associateBy { it.deviceId } }.getOrDefault(_sessions.value)
            }

        fun trust(deviceId: String) =
            viewModelScope.launch {
                gate.attempt { engine.trustDevice(deviceId) }
                loadDevices()
            }

        fun revoke(deviceId: String) =
            run {
                engine.revoke(deviceId)
                loadDevices()
                SyncStep.Idle
            }

        fun rotate(
            password: String?,
            recoveryWords: String?,
        ) = run(SyncStep.Busy.Kind.DERIVING_KEY) {
            when (engine.rotate(password, recoveryWords)) {
                is SyncResult.Synced -> SyncStep.Done(SyncStep.DoneKind.ROTATED)
                else -> SyncStep.Failed(SyncStep.Reason.REJECTED_STATE)
            }
        }

        /** Decision 12: re-seed a server restored from an old backup with this device's copy. */
        fun uploadLocalCopy() =
            run {
                when (engine.uploadLocalCopy()) {
                    is SyncResult.Synced -> SyncStep.Done(SyncStep.DoneKind.UPLOADED)
                    else -> SyncStep.Failed(SyncStep.Reason.REJECTED_STATE)
                }
            }

        /** New master password; proof is the current password or, after recovery, the 24 words. */
        fun changePassword(
            newPassword: String,
            currentPassword: String?,
            recoveryWords: String?,
        ) = run(SyncStep.Busy.Kind.DERIVING_KEY) {
            engine.changePassword(newPassword, currentPassword?.ifBlank { null }, recoveryWords?.ifBlank { null })
            SyncStep.Done(SyncStep.DoneKind.PASSWORD_CHANGED)
        }

        private companion object {
            const val POLL_MS = 2_000L
        }
    }
