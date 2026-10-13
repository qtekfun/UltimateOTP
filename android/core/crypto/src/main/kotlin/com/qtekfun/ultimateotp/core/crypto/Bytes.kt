// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64

/** Base64url without padding, the only binary encoding of the API (canonical decode, like the server). */
object B64u {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val ALPHABET = Regex("^[A-Za-z0-9_-]*$")
    private const val BAD_LENGTH = 1
    private const val QUANTUM = 4

    fun encode(data: ByteArray): String = encoder.encodeToString(data)

    /** @throws CryptoException.InvalidFormat unless [text] is canonical unpadded base64url. */
    fun decode(text: String): ByteArray {
        if (!ALPHABET.matches(text) || text.length % QUANTUM == BAD_LENGTH) {
            invalidFormat("not base64url")
        }
        val data =
            try {
                decoder.decode(text)
            } catch (e: IllegalArgumentException) {
                throw CryptoException.InvalidFormat("not base64url", e)
            }
        if (encode(data) != text) invalidFormat("not canonical base64url")
        return data
    }
}

/** Builds the binary structures of crypto-format.md (big-endian integers). */
internal class ByteWriter {
    private val out = ByteArrayOutputStream()

    fun bytes(b: ByteArray) = apply { out.write(b) }

    fun ascii(s: String) = apply { out.write(s.toByteArray(Charsets.US_ASCII)) }

    fun u8(v: Int) = apply { out.write(v) }

    fun u32(v: Long) = apply { out.write(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(v.toInt()).array()) }

    fun u64(v: Long) = apply { out.write(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(v).array()) }

    fun toByteArray(): ByteArray = out.toByteArray()
}

/** Reads the binary structures of crypto-format.md; any overrun is an invalid format. */
internal class ByteReader(
    private val data: ByteArray,
) {
    var position = 0
        private set

    val remaining: Int get() = data.size - position

    fun bytes(n: Int): ByteArray {
        if (n < 0 || n > remaining) invalidFormat("truncated")
        return data.copyOfRange(position, position + n).also { position += n }
    }

    fun u8(): Int = bytes(1)[0].toInt() and BYTE_MASK

    fun u32(): Long = ByteBuffer.wrap(bytes(Int.SIZE_BYTES)).int.toLong() and UINT_MASK

    fun u64(): Long = ByteBuffer.wrap(bytes(Long.SIZE_BYTES)).long

    fun rest(): ByteArray = bytes(remaining)

    private companion object {
        const val BYTE_MASK = 0xFF
        const val UINT_MASK = 0xFFFFFFFFL
    }
}

internal fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

/** `b64u(SHA-256(data))`, the hash encoding of the contract's signed statements. */
fun sha256B64u(data: ByteArray): String = B64u.encode(sha256(data))

/** Big-endian integer fields for callers outside this module (the vault's stored key record). */
object ByteFields {
    fun u32(v: Long): ByteArray = ByteWriter().u32(v).toByteArray()

    fun readU32(
        data: ByteArray,
        offset: Int,
    ): Long = ByteReader(data.copyOfRange(offset, offset + Int.SIZE_BYTES)).u32()
}
