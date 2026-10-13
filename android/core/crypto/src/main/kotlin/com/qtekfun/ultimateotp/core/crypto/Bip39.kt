// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import java.math.BigInteger

/**
 * BIP-39 English word encoding of raw entropy (crypto-format.md §4.3, §5.4). Only the encoding:
 * no seed derivation, no passphrase.
 */
object Bip39 {
    const val WORDS = 2048
    private const val BITS_PER_WORD = 11
    private const val WORD_MASK = 0x7FF
    private const val BITS_PER_BYTE = 8
    private const val CHECKSUM_DIVISOR = 32
    private const val BYTE_MASK = 0xFF

    val wordlist: List<String> by lazy {
        CryptoResources
            .readLines("bip39-english.txt")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .also { check(it.size == WORDS) { "wordlist must have $WORDS words" } }
    }
    private val index: Map<String, Int> by lazy { wordlist.withIndex().associate { it.value to it.index } }

    /** Entropy (16-32 bytes, multiple of 4) to words with the SHA-256 checksum. */
    fun encode(entropy: ByteArray): List<String> {
        val entBits = entropy.size * BITS_PER_BYTE
        val csBits = entBits / CHECKSUM_DIVISOR
        val checksum = (sha256(entropy)[0].toInt() and BYTE_MASK) shr (BITS_PER_BYTE - csBits)
        val total = BigInteger(1, entropy).shiftLeft(csBits).or(BigInteger.valueOf(checksum.toLong()))
        val n = (entBits + csBits) / BITS_PER_WORD
        return List(n) { i -> wordlist[total.shiftRight(BITS_PER_WORD * (n - 1 - i)).toInt() and WORD_MASK] }
    }

    /**
     * Words back to entropy. @throws CryptoException.InvalidFormat for an unknown word or a wrong
     * checksum (a typo), before anything touches the network.
     */
    fun decode(words: List<String>): ByteArray {
        val n = words.size
        val totalBits = n * BITS_PER_WORD
        val entBits = totalBits * CHECKSUM_DIVISOR / (CHECKSUM_DIVISOR + 1)
        if (n == 0 || entBits % BITS_PER_BYTE != 0) invalidFormat("wrong number of words")
        var total = BigInteger.ZERO
        for (w in words) {
            val i = index[w.trim().lowercase()] ?: invalidFormat("unknown word")
            total = total.shiftLeft(BITS_PER_WORD).or(BigInteger.valueOf(i.toLong()))
        }
        val csBits = totalBits - entBits
        val raw = total.shiftRight(csBits).toByteArray()
        val entropy = ByteArray(entBits / BITS_PER_BYTE)
        val copy = minOf(raw.size, entropy.size)
        System.arraycopy(raw, raw.size - copy, entropy, entropy.size - copy, copy)
        if (encode(entropy) != words.map { it.trim().lowercase() }) invalidFormat("checksum")
        return entropy
    }
}

/** The 256-bit recovery key, shown once as 24 words (crypto-format.md §4.3). */
object RecoveryKey {
    const val BYTES = 32

    fun generate(): ByteArray = Sodium.random(BYTES)

    fun toWords(key: ByteArray): List<String> = Bip39.encode(key)

    fun fromWords(text: String): ByteArray {
        val key = Bip39.decode(text.split(Regex("[\\s,]+")).filter { it.isNotBlank() })
        if (key.size != BYTES) invalidFormat("a recovery key has 24 words")
        return key
    }
}
