// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

/**
 * scrypt (RFC 7914), in plain Kotlin. libsodium only ships scrypt-salsa208sha256 with its own
 * parameter encoding, not the RFC function that Aegis uses for its password slot. Used only to
 * read Aegis vaults: our own formats use Argon2id.
 *
 * Parameters come from the file being read, so they are bounded: at most 256 MiB of memory.
 */
object Scrypt {
    private const val MAX_MEMORY_BYTES = 256L * 1024 * 1024
    private const val MAX_PARALLELISM = 16
    private const val BLOCK_BYTES = 128
    private const val BLOCK_WORDS = 32
    private const val SALSA_WORDS = 16
    private const val INT_BYTES = 4
    private const val BYTE_MASK = 0xFF
    private const val BYTE_BITS = 8
    private const val ROT_A = 7
    private const val ROT_B = 9
    private const val ROT_C = 13
    private const val ROT_D = 18
    private const val DOUBLE_ROUNDS = 4

    /**
     * @param n CPU/memory cost, a power of two greater than 1.
     * @throws CryptoException.InvalidFormat if the parameters are invalid or too expensive.
     */
    fun derive(
        password: ByteArray,
        salt: ByteArray,
        n: Int,
        r: Int,
        p: Int,
        length: Int,
    ): ByteArray {
        if (n < 2 || n and (n - 1) != 0) invalidFormat("scrypt N must be a power of two")
        if (r < 1 || p < 1 || p > MAX_PARALLELISM) invalidFormat("scrypt r or p out of range")
        val memory = BLOCK_BYTES.toLong() * r * (n + p + 2)
        if (memory > MAX_MEMORY_BYTES) invalidFormat("scrypt parameters need too much memory")
        val bytes = Pbkdf2.derive(Pbkdf2.HMAC_SHA256, password, salt, 1, p * BLOCK_BYTES * r)
        val words = IntArray(bytes.size / INT_BYTES) { le32(bytes, it * INT_BYTES) }
        val v = IntArray(BLOCK_WORDS * r * n)
        val xy = IntArray(2 * BLOCK_WORDS * r)
        for (i in 0 until p) smix(words, i * BLOCK_WORDS * r, r, n, v, xy)
        words.forEachIndexed { i, w -> putLe32(bytes, i * INT_BYTES, w) }
        val out = Pbkdf2.derive(Pbkdf2.HMAC_SHA256, password, bytes, 1, length)
        bytes.wipe()
        words.fill(0)
        v.fill(0)
        xy.fill(0)
        return out
    }

    private fun smix(
        b: IntArray,
        bi: Int,
        r: Int,
        n: Int,
        v: IntArray,
        xy: IntArray,
    ) {
        val size = BLOCK_WORDS * r
        val yi = size
        b.copyInto(xy, 0, bi, bi + size)
        for (i in 0 until n) {
            xy.copyInto(v, i * size, 0, size)
            blockMix(xy, yi, r)
        }
        for (i in 0 until n) {
            val j = xy[(2 * r - 1) * SALSA_WORDS] and (n - 1)
            for (k in 0 until size) xy[k] = xy[k] xor v[j * size + k]
            blockMix(xy, yi, r)
        }
        xy.copyInto(b, bi, 0, size)
    }

    /** BlockMix with Salsa20/8 on `xy[0 until 32r]`, using `xy[yi until yi + 32r]` as scratch. */
    private fun blockMix(
        xy: IntArray,
        yi: Int,
        r: Int,
    ) {
        val x = IntArray(SALSA_WORDS)
        xy.copyInto(x, 0, (2 * r - 1) * SALSA_WORDS, (2 * r) * SALSA_WORDS)
        for (i in 0 until 2 * r) {
            for (k in 0 until SALSA_WORDS) x[k] = x[k] xor xy[i * SALSA_WORDS + k]
            salsa208(x)
            x.copyInto(xy, yi + i * SALSA_WORDS)
        }
        for (i in 0 until r) xy.copyInto(xy, i * SALSA_WORDS, yi + 2 * i * SALSA_WORDS, yi + (2 * i + 1) * SALSA_WORDS)
        for (i in 0 until r) xy.copyInto(xy, (i + r) * SALSA_WORDS, yi + (2 * i + 1) * SALSA_WORDS, yi + (2 * i + 2) * SALSA_WORDS)
    }

    @Suppress("LongMethod")
    private fun salsa208(b: IntArray) {
        val x = b.copyOf()
        repeat(DOUBLE_ROUNDS) {
            x[4] = x[4] xor rotl(x[0] + x[12], ROT_A)
            x[8] = x[8] xor rotl(x[4] + x[0], ROT_B)
            x[12] = x[12] xor rotl(x[8] + x[4], ROT_C)
            x[0] = x[0] xor rotl(x[12] + x[8], ROT_D)
            x[9] = x[9] xor rotl(x[5] + x[1], ROT_A)
            x[13] = x[13] xor rotl(x[9] + x[5], ROT_B)
            x[1] = x[1] xor rotl(x[13] + x[9], ROT_C)
            x[5] = x[5] xor rotl(x[1] + x[13], ROT_D)
            x[14] = x[14] xor rotl(x[10] + x[6], ROT_A)
            x[2] = x[2] xor rotl(x[14] + x[10], ROT_B)
            x[6] = x[6] xor rotl(x[2] + x[14], ROT_C)
            x[10] = x[10] xor rotl(x[6] + x[2], ROT_D)
            x[3] = x[3] xor rotl(x[15] + x[11], ROT_A)
            x[7] = x[7] xor rotl(x[3] + x[15], ROT_B)
            x[11] = x[11] xor rotl(x[7] + x[3], ROT_C)
            x[15] = x[15] xor rotl(x[11] + x[7], ROT_D)
            x[1] = x[1] xor rotl(x[0] + x[3], ROT_A)
            x[2] = x[2] xor rotl(x[1] + x[0], ROT_B)
            x[3] = x[3] xor rotl(x[2] + x[1], ROT_C)
            x[0] = x[0] xor rotl(x[3] + x[2], ROT_D)
            x[6] = x[6] xor rotl(x[5] + x[4], ROT_A)
            x[7] = x[7] xor rotl(x[6] + x[5], ROT_B)
            x[4] = x[4] xor rotl(x[7] + x[6], ROT_C)
            x[5] = x[5] xor rotl(x[4] + x[7], ROT_D)
            x[11] = x[11] xor rotl(x[10] + x[9], ROT_A)
            x[8] = x[8] xor rotl(x[11] + x[10], ROT_B)
            x[9] = x[9] xor rotl(x[8] + x[11], ROT_C)
            x[10] = x[10] xor rotl(x[9] + x[8], ROT_D)
            x[12] = x[12] xor rotl(x[15] + x[14], ROT_A)
            x[13] = x[13] xor rotl(x[12] + x[15], ROT_B)
            x[14] = x[14] xor rotl(x[13] + x[12], ROT_C)
            x[15] = x[15] xor rotl(x[14] + x[13], ROT_D)
        }
        for (i in 0 until SALSA_WORDS) b[i] += x[i]
        x.fill(0)
    }

    private fun rotl(
        v: Int,
        bits: Int,
    ) = Integer.rotateLeft(v, bits)

    private fun le32(
        b: ByteArray,
        o: Int,
    ): Int =
        (b[o].toInt() and BYTE_MASK) or
            ((b[o + 1].toInt() and BYTE_MASK) shl BYTE_BITS) or
            ((b[o + 2].toInt() and BYTE_MASK) shl 2 * BYTE_BITS) or
            ((b[o + 3].toInt() and BYTE_MASK) shl 3 * BYTE_BITS)

    private fun putLe32(
        b: ByteArray,
        o: Int,
        v: Int,
    ) {
        for (i in 0 until INT_BYTES) b[o + i] = (v ushr (BYTE_BITS * i)).toByte()
    }
}
