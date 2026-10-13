// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.text.Normalizer
import java.util.Base64

/**
 * Ente Auth's encrypted export (crypto-format.md §11): JSON with Argon2id parameters and a single
 * secretstream chunk. Decrypts to Ente's plain export (one `otpauth://` URI per line).
 */
object EnteExport {
    private const val VERSION = 1
    private const val BASE64_QUANTUM = 4

    /** True if [text] looks like an Ente encrypted export (cheap check before asking for a password). */
    fun isEncryptedExport(text: String): Boolean = runCatching { parse(text) }.isSuccess

    private class Parsed(
        val params: KdfParams,
        val data: ByteArray,
        val header: ByteArray,
    )

    /** kotlinx's SerializationException is an IllegalArgumentException, so one catch covers both. */
    private fun parse(text: String): Parsed =
        try {
            val root = Json.parseToJsonElement(text).jsonObject
            if (root["version"]?.jsonPrimitive?.int != VERSION) invalidFormat("unknown Ente version")
            val kdf = root["kdfParams"]?.jsonObject ?: invalidFormat("missing kdfParams")
            Parsed(
                KdfParams(
                    opsLimit = kdf.long("opsLimit"),
                    memLimit = kdf.long("memLimit"),
                    salt = base64(kdf.string("salt")),
                ).checkReaderLimits(),
                base64(root.string("encryptedData")),
                base64(root.string("encryptionNonce")),
            )
        } catch (e: IllegalArgumentException) {
            throw CryptoException.InvalidFormat("malformed Ente export", e)
        }

    private fun JsonObject.string(name: String): String = this[name]?.jsonPrimitive?.content ?: invalidFormat("missing $name")

    private fun JsonObject.long(name: String): Long = this[name]?.jsonPrimitive?.long ?: invalidFormat("missing $name")

    /** Ente writes standard base64; accept the URL-safe alphabet and missing padding too. */
    private fun base64(text: String): ByteArray {
        val normalized =
            text
                .trim()
                .replace('-', '+')
                .replace('_', '/')
                .trimEnd('=')
        val padded = (normalized.length + BASE64_QUANTUM - 1) / BASE64_QUANTUM * BASE64_QUANTUM
        return Base64.getDecoder().decode(normalized.padEnd(padded, '='))
    }

    /**
     * @return the plain export text.
     * @throws CryptoException.AuthenticationFailed for a wrong password.
     */
    fun decrypt(
        text: String,
        password: String,
    ): String {
        val parsed = parse(text)
        val raw = password.toByteArray(Charsets.UTF_8)
        val nfc = Normalizer.normalize(password, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val candidates = if (raw.contentEquals(nfc)) listOf(raw) else listOf(raw, nfc)
        var failure: CryptoException? = null
        for (candidate in candidates) {
            val key = PasswordKdf.deriveRaw(candidate, parsed.params)
            try {
                val (plain, final) = SecretStreamCodec.Puller(key, parsed.header).pull(parsed.data, ByteArray(0))
                if (!final) invalidFormat("Ente export is not a single final chunk")
                return String(plain, Charsets.UTF_8)
            } catch (e: CryptoException.AuthenticationFailed) {
                failure = e
            } finally {
                key.wipe()
            }
        }
        throw failure ?: CryptoException.AuthenticationFailed()
    }
}
