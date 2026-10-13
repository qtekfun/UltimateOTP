// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Format readers reject each malformed field with a guard clause, and the formats' own constants
// (byte offsets, hex and base64 groups) are the definition of the format.
@file:Suppress("ReturnCount", "ThrowsCount", "CyclomaticComplexMethod", "NestedBlockDepth", "MagicNumber", "LoopWithTooManyJumpStatements")

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.crypto.CryptoException
import com.qtekfun.ultimateotp.core.otp.Base32
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpAuthUri
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.text.Normalizer
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Largest file this module reads; real exports are a few kilobytes. */
internal const val MAX_IMPORT_BYTES = 16 * 1024 * 1024

private const val GCM_TAG_BITS = 128

/** UTF-8 text of [bytes], or null if they are not valid UTF-8 or contain control characters. */
internal fun strictText(bytes: ByteArray): String? {
    val decoder =
        Charsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
    val text =
        try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            return null
        }
    val body = text.removePrefix("")
    return body.takeUnless { s -> s.any { it.isISOControl() && it != '\n' && it != '\r' && it != '\t' } }
}

/** Parses JSON; null if it is not JSON. The parser's own message may quote the input, so it is dropped. */
internal fun parseJson(text: String): JsonElement? = runCatching { Json.parseToJsonElement(text) }.getOrNull()

internal fun JsonElement?.obj(): JsonObject? = this as? JsonObject

internal fun JsonElement?.arr(): JsonArray? = this as? JsonArray

internal fun JsonObject.str(name: String): String? = ((this[name] as? JsonPrimitive)?.takeIf { it !is JsonNull })?.contentOrNull

internal fun JsonObject.int(name: String): Int? =
    (this[name] as? JsonPrimitive)
        ?.let { it.longOrNull ?: it.contentOrNull?.trim()?.toLongOrNull() }
        ?.takeIf {
            it in
                Int.MIN_VALUE..Int.MAX_VALUE
        }?.toInt()

internal fun JsonObject.long(name: String): Long? =
    (this[name] as? JsonPrimitive)?.let {
        it.longOrNull
            ?: it.contentOrNull?.trim()?.toLongOrNull()
    }

internal fun JsonObject.bool(name: String): Boolean = (this[name] as? JsonPrimitive)?.booleanOrNull ?: false

internal fun base64(text: String): ByteArray {
    val normalized =
        text
            .trim()
            .replace('-', '+')
            .replace('_', '/')
            .trimEnd('=')
    val padded = (normalized.length + 3) / 4 * 4
    return try {
        Base64.getDecoder().decode(normalized.padEnd(padded, '='))
    } catch (_: IllegalArgumentException) {
        throw CryptoException.InvalidFormat("not base64")
    }
}

internal fun hex(text: String): ByteArray {
    val t = text.trim()
    val digits = t.map { Character.digit(it, 16) }
    if (t.length % 2 != 0 || digits.any { it < 0 }) throw CryptoException.InvalidFormat("not hex")
    return ByteArray(t.length / 2) { (digits[it * 2] * 16 + digits[it * 2 + 1]).toByte() }
}

/** AES-256-GCM with a 128-bit tag; [data] is ciphertext followed by the tag (JCA layout). */
internal fun aesGcmOpen(
    key: ByteArray,
    nonce: ByteArray,
    data: ByteArray,
    aad: ByteArray? = null,
): ByteArray {
    if (key.size != 32 || nonce.isEmpty() || data.size < GCM_TAG_BITS / 8) throw CryptoException.InvalidFormat("bad AES-GCM input")
    return try {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        if (aad != null) cipher.updateAAD(aad)
        cipher.doFinal(data)
    } catch (e: AEADBadTagException) {
        throw CryptoException.AuthenticationFailed(cause = e)
    } catch (e: javax.crypto.BadPaddingException) {
        throw CryptoException.AuthenticationFailed(cause = e)
    }
}

/**
 * Password byte strings to try: the UTF-8 bytes as typed and, if different, the NFC form (the
 * apps do not agree on normalisation, and a keyboard may type either).
 */
internal fun passwordCandidates(password: String): List<ByteArray> {
    val raw = password.toByteArray(Charsets.UTF_8)
    val nfc = Normalizer.normalize(password, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
    return if (raw.contentEquals(nfc)) listOf(raw) else listOf(raw, nfc)
}

/** A base32 secret as exported by apps: spaces, dashes, case and padding vary. */
internal fun secretOf(text: String?): ByteArray = Base32.decode(text ?: throw IllegalArgumentException("missing secret"))

/** `otpauth://` or Steam's `steam://SECRET`, as Bitwarden and Proton write them. */
internal fun parseUriOrSteam(uri: String): OtpParams {
    val text = uri.trim()
    if (text.startsWith("steam://", ignoreCase = true)) {
        val secret = Base32.decode(text.substring("steam://".length).substringBefore('?'))
        return OtpParams(OtpType.STEAM, secret, OtpAlgorithm.SHA1, OtpParams.STEAM_DIGITS, issuer = "Steam")
    }
    return OtpAuthUri.parse(text)
}

/** Runs [block] for every entry, counting those that throw (bad secret, unknown type...) as rejected. */
internal inline fun <T> collectEntries(
    items: Iterable<T>,
    block: (T) -> ImportedAccount?,
): Pair<List<ImportedAccount>, Int> {
    val out = mutableListOf<ImportedAccount>()
    var rejected = 0
    for (item in items) {
        try {
            block(item)?.let(out::add) ?: rejected++
        } catch (_: IllegalArgumentException) {
            rejected++
        }
    }
    return out to rejected
}
