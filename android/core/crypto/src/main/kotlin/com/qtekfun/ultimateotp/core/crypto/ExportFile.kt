// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import java.io.ByteArrayOutputStream

/**
 * The password-protected `.uotp` export (crypto-format.md §10): Argon2id + secretstream, every
 * chunk authenticating the 65-byte header.
 */
object ExportFile {
    const val MAGIC = "UOTPEXP1"
    const val DEFAULT_CHUNK = 65_536
    const val MAX_CHUNK = 1 shl 20
    private const val HEADER_BYTES = 65

    fun isExport(data: ByteArray): Boolean = data.size >= MAGIC.length && String(data.copyOf(MAGIC.length), Charsets.US_ASCII) == MAGIC

    fun write(
        plaintext: ByteArray,
        password: String,
        ladder: List<Pair<Long, Long>> = PasswordKdf.SENSITIVE_LADDER,
        chunkSize: Int = DEFAULT_CHUNK,
    ): ByteArray {
        require(chunkSize in 1..MAX_CHUNK) { "bad chunk size" }
        val (params, key) = PasswordKdf.deriveNew(password, ladder)
        try {
            val pusher = SecretStreamCodec.Pusher(key)
            val header =
                ByteWriter()
                    .ascii(MAGIC)
                    .u8(KdfParams.ALG_ARGON2ID13)
                    .u32(params.opsLimit)
                    .u64(params.memLimit)
                    .bytes(params.salt)
                    .u32(chunkSize.toLong())
                    .bytes(pusher.header)
                    .toByteArray()
            val out = ByteArrayOutputStream(header.size + plaintext.size + plaintext.size / chunkSize * SecretStreamCodec.ABYTES)
            out.write(header)
            var offset = 0
            do {
                val end = minOf(offset + chunkSize, plaintext.size)
                // A plaintext that fills its last chunk exactly gets an empty final chunk.
                val final = end == plaintext.size && (end - offset) < chunkSize
                out.write(pusher.push(plaintext.copyOfRange(offset, end), header, final))
                offset = end
            } while (!final)
            return out.toByteArray()
        } finally {
            key.wipe()
        }
    }

    /**
     * @throws CryptoException.AuthenticationFailed for a wrong password or a tampered file;
     *   [CryptoException.InvalidFormat] for a truncated or malformed one.
     */
    fun read(
        file: ByteArray,
        password: String,
    ): ByteArray {
        if (!isExport(file) || file.size < HEADER_BYTES) invalidFormat("not a .uotp export")
        val r = ByteReader(file)
        val header = file.copyOf(HEADER_BYTES)
        r.bytes(MAGIC.length)
        if (r.u8() != KdfParams.ALG_ARGON2ID13) invalidFormat("unknown KDF")
        val params = KdfParams(r.u32(), r.u64(), r.bytes(KdfParams.SALT_BYTES)).checkReaderLimits()
        val chunkSize = r.u32()
        if (chunkSize !in 1..MAX_CHUNK.toLong()) invalidFormat("bad chunk size")
        val ssHeader = r.bytes(SecretStreamCodec.HEADER_BYTES)
        val key = PasswordKdf.derive(password, params)
        try {
            val puller = SecretStreamCodec.Puller(key, ssHeader)
            val out = ByteArrayOutputStream(r.remaining)
            val fullChunk = chunkSize.toInt() + SecretStreamCodec.ABYTES
            var final = false
            while (!final) {
                if (r.remaining == 0) invalidFormat("truncated export")
                val (plain, isFinal) = puller.pull(r.bytes(minOf(fullChunk, r.remaining)), header)
                if (!isFinal && plain.size != chunkSize.toInt()) invalidFormat("short chunk")
                out.write(plain)
                final = isFinal
            }
            if (r.remaining != 0) invalidFormat("trailing data")
            return out.toByteArray()
        } finally {
            key.wipe()
        }
    }
}
