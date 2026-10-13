// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.box.Box

/** The vault key sealed to a device (crypto-format.md §5.3). */
object SealedVaultKey {
    private const val LABEL = "UOTP-GRANT-v1"

    /** `crypto_box_seal("UOTP-GRANT-v1" || u32be epoch || VK || account_id, recipient)`. */
    fun seal(
        vaultKey: ByteArray,
        keyEpoch: Long,
        accountId: String,
        recipientX25519: ByteArray,
    ): ByteArray {
        Sodium.init()
        val plain =
            ByteWriter()
                .ascii(LABEL)
                .u32(keyEpoch)
                .bytes(vaultKey)
                .bytes(accountId.toByteArray())
                .toByteArray()
        try {
            return Box.seal(plain.asUByteArray(), recipientX25519.asUByteArray()).asByteArray()
        } finally {
            plain.wipe()
        }
    }

    /**
     * Opens a sealed key after the caller verified its seal signature with a pinned device.
     * @throws CryptoException if it is not for [accountId] / [keyEpoch].
     */
    fun open(
        keys: DeviceKeys,
        sealed: ByteArray,
        keyEpoch: Long,
        accountId: String,
    ): ByteArray {
        val plain = keys.openSealed(sealed)
        val r = ByteReader(plain)
        val label = String(r.bytes(LABEL.length), Charsets.US_ASCII)
        val epoch = r.u32()
        val vk = r.bytes(Aead.KEY_BYTES)
        val acc = String(r.rest(), Charsets.UTF_8)
        plain.wipe()
        if (label != LABEL || epoch != keyEpoch || acc != accountId) {
            vk.wipe()
            throw CryptoException.AuthenticationFailed("sealed key is for another account or epoch")
        }
        return vk
    }
}

/** The six words both screens show while pairing (crypto-format.md §5.4). */
object Sas {
    private const val WORDS = 6
    private const val BITS_PER_WORD = 11
    private const val WORD_MASK = 0x7FF
    private const val DIGEST_BYTES = 32
    private const val USED_BYTES = 9
    private const val SPARE_BITS = USED_BYTES * 8 - WORDS * BITS_PER_WORD

    fun words(
        approverEd25519: ByteArray,
        joinerEd25519: ByteArray,
        joinerX25519: ByteArray,
    ): List<String> {
        Sodium.init()
        val input =
            ByteWriter()
                .ascii("UOTP-SAS-v1")
                .bytes(approverEd25519)
                .bytes(joinerEd25519)
                .bytes(joinerX25519)
                .toByteArray()
        val digest =
            com.ionspin.kotlin.crypto.generichash.GenericHash
                .genericHash(input.asUByteArray(), DIGEST_BYTES, null)
                .asByteArray()
        val bits = java.math.BigInteger(1, digest.copyOf(USED_BYTES)).shiftRight(SPARE_BITS)
        return List(WORDS) { i -> Bip39.wordlist[bits.shiftRight(BITS_PER_WORD * (WORDS - 1 - i)).toInt() and WORD_MASK] }
    }
}
