// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

/**
 * The contract's signed statements (contracts/openapi.yaml; crypto-format.md §5, §7, §12.1):
 * UTF-8 lines joined by `\n`, starting with a versioned domain tag.
 */
object Statements {
    private fun lines(vararg parts: Any): ByteArray = parts.joinToString("\n").toByteArray(Charsets.UTF_8)

    fun request(
        method: String,
        target: String,
        device: String,
        timestamp: Long,
        nonce: String,
        body: ByteArray,
    ): ByteArray = lines("UOTP-REQ-v1", method.uppercase(), target, device, timestamp, nonce, sha256B64u(body))

    /** One live item of the manifest: its id, version and blob. */
    class ManifestEntry(
        val itemId: String,
        val version: Long,
        val blob: ByteArray,
    )

    /** `item_id:version:b64u(SHA-256(blob))\n` over live items sorted by id. */
    fun manifest(live: Collection<ManifestEntry>): ByteArray =
        live
            .sortedBy { it.itemId }
            .joinToString("") { "${it.itemId}:${it.version}:${sha256B64u(it.blob)}\n" }
            .toByteArray(Charsets.US_ASCII)

    fun head(
        accountId: String,
        version: Long,
        keyEpoch: Long,
        signedBy: String,
        manifest: ByteArray,
    ): ByteArray = lines("UOTP-HEAD-v1", accountId, version, keyEpoch, signedBy, sha256B64u(manifest))

    fun seal(
        accountId: String,
        keyEpoch: Long,
        recipientDeviceId: String,
        sealed: ByteArray,
    ): ByteArray = lines("UOTP-SEAL-v1", accountId, keyEpoch, recipientDeviceId, sha256B64u(sealed))

    fun device(
        accountId: String,
        deviceId: String,
        ed25519B64u: String,
        x25519B64u: String,
    ): ByteArray = lines("UOTP-DEVICE-v1", accountId, deviceId, ed25519B64u, x25519B64u)
}
