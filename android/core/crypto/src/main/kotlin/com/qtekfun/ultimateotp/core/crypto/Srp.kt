// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.kdf.Kdf
import java.math.BigInteger
import java.security.MessageDigest

/**
 * SRP-6a client (crypto-format.md §4.4): RFC 5054 group arithmetic, proofs as Ente's server
 * (`M1 = H(PAD(A) || PAD(B) || PAD(S))`, `M2 = H(PAD(A) || M1 || PAD(S))`).
 */
class SrpGroup(
    val n: BigInteger,
    val g: BigInteger,
    val hash: String,
) {
    val size: Int = (n.bitLength() + BITS_PER_BYTE - 1) / BITS_PER_BYTE

    fun pad(x: BigInteger): ByteArray {
        val raw = x.toByteArray().let { if (it.size > size) it.copyOfRange(it.size - size, it.size) else it }
        return ByteArray(size - raw.size) + raw
    }

    fun h(vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance(hash).run {
            parts.forEach { update(it) }
            digest()
        }

    fun hInt(vararg parts: ByteArray): BigInteger = BigInteger(1, h(*parts))

    val k: BigInteger get() = hInt(pad(n), pad(g))

    /** `x = H(s || H(I || ":" || P))`. */
    fun x(
        identity: ByteArray,
        password: ByteArray,
        salt: ByteArray,
    ): BigInteger = hInt(salt, h(identity, ":".toByteArray(), password))

    fun verifier(x: BigInteger): BigInteger = g.modPow(x, n)

    companion object {
        private const val BITS_PER_BYTE = 8
        private const val G4096 = 5L

        /** RFC 5054 §A.5, g = 5, SHA-256: the UltimateOTP (and Ente) parameters. */
        val RFC5054_4096: SrpGroup by lazy {
            val text = requireNotNull(SrpGroup::class.java.getResourceAsStream("rfc5054-4096.hex")).bufferedReader().readText()
            SrpGroup(BigInteger(text.filter { it.isLetterOrDigit() }, 16), BigInteger.valueOf(G4096), "SHA-256")
        }
    }
}

/** What the client sends at bootstrap or password change. */
class SrpSetup(
    val srpUserId: String,
    val salt: ByteArray,
    val verifier: ByteArray,
)

object Srp {
    const val SALT_BYTES = 16
    private const val LOGIN_SUBKEY_BYTES = 16
    private const val LOGIN_CONTEXT = "loginctx"
    private const val LOGIN_SUBKEY_ID = 1u
    private const val PRIVATE_BYTES = 64

    /** `KDF(KEK_pw, 1, "loginctx")[0..16]`: never reveals the KEK. */
    fun loginSubkey(kekPw: ByteArray): ByteArray {
        Sodium.init()
        return Kdf
            .deriveFromKey(LOGIN_SUBKEY_ID, Aead.KEY_BYTES, LOGIN_CONTEXT, kekPw.asUByteArray())
            .asByteArray()
            .copyOf(LOGIN_SUBKEY_BYTES)
    }

    fun setup(
        kekPw: ByteArray,
        srpUserId: String =
            java.util.UUID
                .randomUUID()
                .toString(),
        salt: ByteArray = Sodium.random(SALT_BYTES),
        group: SrpGroup = SrpGroup.RFC5054_4096,
    ): SrpSetup {
        val x = group.x(srpUserId.toByteArray(), loginSubkey(kekPw), salt)
        return SrpSetup(srpUserId, salt, group.pad(group.verifier(x)))
    }

    /** One login attempt: send [publicA], then [proof] the server's `B`. */
    class Session internal constructor(
        private val group: SrpGroup,
        private val x: BigInteger,
        private val a: BigInteger,
    ) {
        val publicA: ByteArray = group.pad(group.g.modPow(a, group.n))
        private var expectedM2: ByteArray? = null

        /**
         * @return `M1` for the server's [serverB].
         * @throws CryptoException.AuthenticationFailed for a degenerate `B` (malicious server).
         */
        fun proof(serverB: ByteArray): ByteArray {
            val n = group.n
            val b = BigInteger(1, serverB)
            if (b.mod(n).signum() == 0) throw CryptoException.AuthenticationFailed("bad SRP B")
            val u = group.hInt(publicA, group.pad(b))
            if (u.signum() == 0) throw CryptoException.AuthenticationFailed("bad SRP u")
            val base = b.subtract(group.k.multiply(group.verifier(x))).mod(n)
            val s = group.pad(base.modPow(a.add(u.multiply(x)), n))
            val m1 = group.h(publicA, group.pad(b), s)
            expectedM2 = group.h(publicA, m1, s)
            return m1
        }

        /** True only if the server proved it holds the verifier. */
        fun verifyServer(m2: ByteArray): Boolean = expectedM2?.let { MessageDigest.isEqual(it, m2) } ?: false
    }

    fun start(
        kekPw: ByteArray,
        srpUserId: String,
        salt: ByteArray,
        group: SrpGroup = SrpGroup.RFC5054_4096,
        privateA: ByteArray = Sodium.random(PRIVATE_BYTES),
    ): Session = Session(group, group.x(srpUserId.toByteArray(), loginSubkey(kekPw), salt), BigInteger(1, privateA))

    /** For the RFC 5054 test vector, where the password is used directly. */
    internal fun startRaw(
        group: SrpGroup,
        identity: ByteArray,
        password: ByteArray,
        salt: ByteArray,
        privateA: ByteArray,
    ): Session = Session(group, group.x(identity, password, salt), BigInteger(1, privateA))
}
