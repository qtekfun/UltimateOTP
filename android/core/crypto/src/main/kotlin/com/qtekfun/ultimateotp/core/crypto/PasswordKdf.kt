// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.sun.jna.Library
import com.sun.jna.NativeLong
import java.lang.reflect.Proxy
import java.text.Normalizer

/**
 * Argon2id parameters (crypto-format.md §4.1): `params_block` on the wire, the API's
 * `password_kdf`.
 */
class KdfParams(
    val opsLimit: Long,
    val memLimit: Long,
    salt: ByteArray,
) {
    private val saltBytes = salt.copyOf()
    val salt: ByteArray get() = saltBytes.copyOf()

    init {
        if (saltBytes.size != SALT_BYTES) invalidFormat("salt must be $SALT_BYTES bytes")
    }

    /** `u8 alg || u32be opslimit || u64be memlimit || salt[16]` (29 bytes). */
    fun encode(): ByteArray =
        ByteWriter()
            .u8(ALG_ARGON2ID13)
            .u32(opsLimit)
            .u64(memLimit)
            .bytes(saltBytes)
            .toByteArray()

    /** Reader limits: refuse parameters a hostile server or file could use to stall the device. */
    fun checkReaderLimits(): KdfParams =
        apply {
            if (opsLimit !in MIN_OPS..MAX_OPS || memLimit !in MIN_MEM..MAX_MEM) {
                invalidFormat("Argon2id parameters out of range")
            }
        }

    override fun equals(other: Any?): Boolean =
        other is KdfParams && opsLimit == other.opsLimit &&
            memLimit == other.memLimit && saltBytes.contentEquals(other.saltBytes)

    override fun hashCode(): Int = (opsLimit * HASH + memLimit).hashCode() * HASH.toInt() + saltBytes.contentHashCode()

    companion object {
        const val ALG_ARGON2ID13 = 2
        const val SALT_BYTES = 16
        const val ENCODED_BYTES = 29
        const val MIN_OPS = 1L
        const val MAX_OPS = 4096L
        const val MIN_MEM = 8192L
        const val MAX_MEM = 1L shl 30
        private const val HASH = 31L

        fun decode(bytes: ByteArray): KdfParams {
            if (bytes.size != ENCODED_BYTES) invalidFormat("bad KDF parameter block")
            val r = ByteReader(bytes)
            if (r.u8() != ALG_ARGON2ID13) invalidFormat("unknown KDF algorithm")
            return KdfParams(r.u32(), r.u64(), r.bytes(SALT_BYTES))
        }
    }
}

/**
 * Password key derivation with `crypto_pwhash` (Argon2id). It calls libsodium directly instead of
 * the bindings' `PasswordHash.pwhash`, which passes `String.length` (UTF-16 units) as the byte
 * length of the UTF-8 password and a 64-bit `memlimit` where C expects `size_t`
 * (crypto-format.md §1.3).
 */
object PasswordKdf {
    const val KEY_BYTES = 32
    private const val MIB = 1L shl 20

    /**
     * Writer parameters: libsodium's sensitive limits, then half the memory and twice the passes
     * when the device cannot allocate it (crypto-format.md §4.1). Never weaker than the last rung.
     */
    val SENSITIVE_LADDER: List<Pair<Long, Long>> =
        listOf(
            4L to 1024 * MIB,
            8L to 512 * MIB,
            16L to 256 * MIB,
        )

    /**
     * The rungs of [SENSITIVE_LADDER] that fit in [availableBytes] with headroom. A failed
     * allocation is not reliable on Android: with memory overcommit the 1 GiB mmap may succeed
     * and the low-memory killer then ends the app, so the caller passes the free memory
     * (`ActivityManager.MemoryInfo.availMem`) and the ladder starts where it fits.
     */
    fun ladderFor(availableBytes: Long): List<Pair<Long, Long>> {
        val fitting = SENSITIVE_LADDER.filter { (_, mem) -> mem * HEADROOM_NUM / HEADROOM_DEN <= availableBytes }
        return fitting.ifEmpty { listOf(SENSITIVE_LADDER.last()) }
    }

    private const val HEADROOM_NUM = 3
    private const val HEADROOM_DEN = 2

    /** NFC, then UTF-8 (crypto-format.md §2). */
    fun passwordBytes(password: String): ByteArray = Normalizer.normalize(password, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)

    /** Derives with stored [params] (reader side). */
    fun derive(
        password: String,
        params: KdfParams,
    ): ByteArray = deriveRaw(passwordBytes(password), params.checkReaderLimits())

    /** Derives with the raw UTF-8 bytes of a password (Ente compatibility, crypto-format.md §11). */
    fun deriveRaw(
        password: ByteArray,
        params: KdfParams,
    ): ByteArray {
        Sodium.init()
        val out = ByteArray(KEY_BYTES)
        val rc = pwhash(out, password, params)
        if (rc != 0) throw CryptoException.KdfFailed("crypto_pwhash failed (out of memory?)")
        return out
    }

    /**
     * New salt and the strongest rung of [ladder] the device can run (writer side).
     * @return the parameters actually used and the derived key.
     */
    fun deriveNew(
        password: String,
        ladder: List<Pair<Long, Long>> = SENSITIVE_LADDER,
    ): Pair<KdfParams, ByteArray> {
        Sodium.init()
        val bytes = passwordBytes(password)
        try {
            val salt = Sodium.random(KdfParams.SALT_BYTES)
            for ((ops, mem) in ladder) {
                val params = KdfParams(ops, mem, salt)
                val out = ByteArray(KEY_BYTES)
                if (pwhash(out, bytes, params) == 0) return params to out
            }
        } finally {
            bytes.wipe()
        }
        throw CryptoException.KdfFailed("Argon2id needs at least ${ladder.last().second / MIB} MiB")
    }

    private fun pwhash(
        out: ByteArray,
        password: ByteArray,
        params: KdfParams,
    ): Int {
        val handler = Proxy.getInvocationHandler(LibsodiumInitializer.sodiumJna) as Library.Handler
        val function = handler.nativeLibrary.getFunction("crypto_pwhash")
        // int crypto_pwhash(uchar *out, ull outlen, const char *passwd, ull passwdlen,
        //                   const uchar *salt, ull opslimit, size_t memlimit, int alg)
        return function.invokeInt(
            arrayOf(
                out,
                out.size.toLong(),
                password,
                password.size.toLong(),
                params.salt,
                params.opsLimit,
                NativeLong(params.memLimit),
                KdfParams.ALG_ARGON2ID13,
            ),
        )
    }
}
