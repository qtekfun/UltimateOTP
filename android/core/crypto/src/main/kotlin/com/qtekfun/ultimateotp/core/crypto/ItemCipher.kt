// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.kdf.Kdf
import com.ionspin.kotlin.crypto.util.LibsodiumUtil
import com.ionspin.kotlin.crypto.util.PaddingException
import java.nio.ByteBuffer
import java.util.UUID

/** Where an item blob belongs; all of it is bound into the AEAD (crypto-format.md §6.2). */
data class ItemBinding(
    val accountId: String,
    val itemId: UUID,
    val itemVersion: Long,
    val keyEpoch: Long,
) {
    init {
        require(accountId.toByteArray().size <= MAX_ACCOUNT_ID) { "account id too long" }
    }

    internal fun ad(): ByteArray {
        val acc = accountId.toByteArray(Charsets.UTF_8)
        val id = ByteBuffer.allocate(UUID_BYTES).putLong(itemId.mostSignificantBits).putLong(itemId.leastSignificantBits)
        return ByteWriter()
            .ascii(LABEL)
            .u8(acc.size)
            .bytes(acc)
            .bytes(id.array())
            .u64(itemVersion)
            .u32(keyEpoch)
            .toByteArray()
    }

    private companion object {
        const val LABEL = "UOTP-ITEM-v1"
        const val UUID_BYTES = 16
        const val MAX_ACCOUNT_ID = 255
    }
}

/** Item blobs: `u8 1 || u32be key_epoch || nonce || AEAD(K_item, padded JSON, AD)`. */
object ItemCipher {
    const val VERSION = 1
    const val PAD_BLOCK = 256
    const val MAX_PADDED = 240 * PAD_BLOCK
    private const val ITEM_CONTEXT = "uotpitem"
    private const val ITEM_SUBKEY_ID = 1u
    private const val HEADER = 1 + Int.SIZE_BYTES + Aead.NONCE_BYTES

    /** `K_item = KDF(VK, 1, "uotpitem")`. */
    fun itemKey(vaultKey: ByteArray): ByteArray {
        Sodium.init()
        return Kdf.deriveFromKey(ITEM_SUBKEY_ID, Aead.KEY_BYTES, ITEM_CONTEXT, vaultKey.asUByteArray()).asByteArray()
    }

    fun encrypt(
        itemKey: ByteArray,
        binding: ItemBinding,
        plaintext: ByteArray,
        nonce: ByteArray = Sodium.random(Aead.NONCE_BYTES),
    ): ByteArray {
        Sodium.init()
        val padded = LibsodiumUtil.pad(plaintext.asUByteArray(), PAD_BLOCK).asByteArray()
        if (padded.size > MAX_PADDED) invalidFormat("item too large")
        val ct = Aead.encrypt(itemKey, nonce, padded, binding.ad())
        return ByteWriter()
            .u8(VERSION)
            .u32(binding.keyEpoch)
            .bytes(nonce)
            .bytes(ct)
            .toByteArray()
    }

    /** The key epoch a blob was written with (to pick the right vault key). */
    fun keyEpochOf(blob: ByteArray): Long {
        val r = ByteReader(blob)
        if (r.u8() != VERSION) invalidFormat("unknown item version")
        return r.u32()
    }

    /** @throws CryptoException.AuthenticationFailed if the blob does not belong to [binding]. */
    fun decrypt(
        itemKey: ByteArray,
        binding: ItemBinding,
        blob: ByteArray,
    ): ByteArray {
        if (blob.size < HEADER + Aead.TAG_BYTES + PAD_BLOCK) invalidFormat("item blob too short")
        val r = ByteReader(blob)
        if (r.u8() != VERSION) invalidFormat("unknown item version")
        if (r.u32() != binding.keyEpoch) throw CryptoException.AuthenticationFailed("key epoch mismatch")
        val nonce = r.bytes(Aead.NONCE_BYTES)
        val padded = Aead.decrypt(itemKey, nonce, r.rest(), binding.ad())
        return try {
            LibsodiumUtil.unpad(padded.asUByteArray(), PAD_BLOCK).asByteArray()
        } catch (e: PaddingException) {
            throw CryptoException.InvalidFormat("bad padding", e)
        }
    }
}
