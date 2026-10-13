// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.kdf.Kdf

/** The three wrap kinds of crypto-format.md §4.2. */
enum class WrapKind(
    val code: Int,
) {
    PASSWORD(1),
    RECOVERY(2),
    RECOVERY_KEK(3),
}

/** `u8 0x01 || nonce[24] || AEAD(K, nonce, payload, "UOTP-WRAP-v1" || kind || epoch || params)`. */
object KeyWrap {
    const val VERSION = 1
    const val WRAPPED_KEY_BYTES = 32
    const val BYTES = 1 + Aead.NONCE_BYTES + WRAPPED_KEY_BYTES + Aead.TAG_BYTES
    private const val LABEL = "UOTP-WRAP-v1"

    fun wrap(
        kind: WrapKind,
        key: ByteArray,
        payload: ByteArray,
        keyEpoch: Long,
        params: KdfParams?,
        nonce: ByteArray = Sodium.random(Aead.NONCE_BYTES),
    ): ByteArray {
        require(payload.size == WRAPPED_KEY_BYTES) { "payload must be a 32-byte key" }
        val ct = Aead.encrypt(key, nonce, payload, ad(kind, keyEpoch, params))
        return ByteWriter()
            .u8(VERSION)
            .bytes(nonce)
            .bytes(ct)
            .toByteArray()
    }

    /** @throws CryptoException.AuthenticationFailed for a wrong password or recovery key. */
    fun unwrap(
        kind: WrapKind,
        key: ByteArray,
        wrap: ByteArray,
        keyEpoch: Long,
        params: KdfParams?,
    ): ByteArray {
        if (wrap.size != BYTES) invalidFormat("bad wrap length")
        val r = ByteReader(wrap)
        if (r.u8() != VERSION) invalidFormat("unknown wrap version")
        val nonce = r.bytes(Aead.NONCE_BYTES)
        return Aead.decrypt(key, nonce, r.rest(), ad(kind, keyEpoch, params))
    }

    private fun ad(
        kind: WrapKind,
        keyEpoch: Long,
        params: KdfParams?,
    ): ByteArray =
        ByteWriter()
            .ascii(LABEL)
            .u8(kind.code)
            .u32(keyEpoch)
            .bytes(params?.encode() ?: ByteArray(0))
            .toByteArray()
}

/** The API's `KeyBundle` (base64url fields), built from the wraps (crypto-format.md §4.2). */
data class KeyBundle(
    val passwordWrap: String?,
    val passwordKdf: String?,
    val recoveryWrap: String,
)

/** Creates and opens the account's password and recovery wraps of the vault key. */
object VaultKeyWraps {
    private const val RECOVERY_CONTEXT = "uotprcvy"
    private const val RECOVERY_SUBKEY_ID = 1u

    /** `KEK_rk = crypto_kdf_derive_from_key(32, 1, "uotprcvy", RK)`. */
    fun recoveryKek(recoveryKey: ByteArray): ByteArray {
        Sodium.init()
        return Kdf
            .deriveFromKey(RECOVERY_SUBKEY_ID, PasswordKdf.KEY_BYTES, RECOVERY_CONTEXT, recoveryKey.asUByteArray())
            .asByteArray()
    }

    /**
     * The bundle for [vaultKey] of [keyEpoch]. [kekPw] and [params] come from
     * [PasswordKdf.deriveNew]; both null means the paranoid setting (no password path).
     */
    fun bundle(
        vaultKey: ByteArray,
        keyEpoch: Long,
        kekRk: ByteArray,
        kekPw: ByteArray?,
        params: KdfParams?,
    ): KeyBundle {
        val recovery = KeyWrap.wrap(WrapKind.RECOVERY, kekRk, vaultKey, keyEpoch, null)
        if (kekPw == null || params == null) return KeyBundle(null, null, B64u.encode(recovery))
        val password =
            KeyWrap.wrap(WrapKind.PASSWORD, kekPw, vaultKey, keyEpoch, params) +
                KeyWrap.wrap(WrapKind.RECOVERY_KEK, kekPw, kekRk, 0, params)
        return KeyBundle(B64u.encode(password), B64u.encode(params.encode()), B64u.encode(recovery))
    }

    /** Result of opening the password wrap: the vault key and, when present, `KEK_rk`. */
    class PasswordOpened(
        val vaultKey: ByteArray,
        val recoveryKek: ByteArray?,
    )

    fun openWithPassword(
        password: String,
        passwordWrap: String,
        passwordKdf: String,
        keyEpoch: Long,
    ): PasswordOpened {
        val params = KdfParams.decode(B64u.decode(passwordKdf)).checkReaderLimits()
        val kek = PasswordKdf.derive(password, params)
        try {
            return openWithKek(kek, passwordWrap, params, keyEpoch)
        } finally {
            kek.wipe()
        }
    }

    fun openWithKek(
        kekPw: ByteArray,
        passwordWrap: String,
        params: KdfParams,
        keyEpoch: Long,
    ): PasswordOpened {
        val bytes = B64u.decode(passwordWrap)
        if (bytes.size != KeyWrap.BYTES && bytes.size != 2 * KeyWrap.BYTES) {
            invalidFormat("bad password wrap length")
        }
        val vk = KeyWrap.unwrap(WrapKind.PASSWORD, kekPw, bytes.copyOfRange(0, KeyWrap.BYTES), keyEpoch, params)
        val rk =
            if (bytes.size == 2 * KeyWrap.BYTES) {
                KeyWrap.unwrap(WrapKind.RECOVERY_KEK, kekPw, bytes.copyOfRange(KeyWrap.BYTES, bytes.size), 0, params)
            } else {
                null
            }
        return PasswordOpened(vk, rk)
    }

    fun openWithRecoveryKey(
        recoveryKey: ByteArray,
        recoveryWrap: String,
        keyEpoch: Long,
    ): ByteArray {
        val kek = recoveryKek(recoveryKey)
        try {
            return KeyWrap.unwrap(WrapKind.RECOVERY, kek, B64u.decode(recoveryWrap), keyEpoch, null)
        } finally {
            kek.wipe()
        }
    }
}
