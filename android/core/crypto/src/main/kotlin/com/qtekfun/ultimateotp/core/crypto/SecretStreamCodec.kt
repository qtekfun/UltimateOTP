// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.crypto

import com.ionspin.kotlin.crypto.SecretStreamXChaCha20Poly1305State
import com.ionspin.kotlin.crypto.secretstream.SecretStream
import com.ionspin.kotlin.crypto.secretstream.SecretStreamCorruptedOrTamperedDataException

/** `crypto_secretstream_xchacha20poly1305`, as used by the export file and Ente's export. */
internal object SecretStreamCodec {
    const val HEADER_BYTES = 24
    const val ABYTES = 17
    const val TAG_MESSAGE: UByte = 0u
    const val TAG_FINAL: UByte = 3u

    class Pusher(
        key: ByteArray,
    ) {
        private val state: SecretStreamXChaCha20Poly1305State
        val header: ByteArray

        init {
            Sodium.init()
            val sh = SecretStream.xChaCha20Poly1305InitPush(key.asUByteArray())
            state = sh.state
            header = sh.header.asByteArray()
        }

        fun push(
            message: ByteArray,
            ad: ByteArray,
            final: Boolean,
        ): ByteArray =
            SecretStream
                .xChaCha20Poly1305Push(
                    state,
                    message.asUByteArray(),
                    ad.asUByteArray(),
                    if (final) TAG_FINAL else TAG_MESSAGE,
                ).asByteArray()
    }

    class Puller(
        key: ByteArray,
        header: ByteArray,
    ) {
        private val state: SecretStreamXChaCha20Poly1305State

        init {
            Sodium.init()
            if (header.size != HEADER_BYTES) invalidFormat("bad secretstream header")
            state = SecretStream.xChaCha20Poly1305InitPull(key.asUByteArray(), header.asUByteArray()).state
        }

        /** @return the plaintext and whether the chunk carried `TAG_FINAL`. */
        fun pull(
            chunk: ByteArray,
            ad: ByteArray,
        ): Pair<ByteArray, Boolean> {
            if (chunk.size < ABYTES) invalidFormat("truncated chunk")
            val out =
                try {
                    SecretStream.xChaCha20Poly1305Pull(state, chunk.asUByteArray(), ad.asUByteArray())
                } catch (e: SecretStreamCorruptedOrTamperedDataException) {
                    throw CryptoException.AuthenticationFailed(cause = e)
                }
            return when (out.tag) {
                TAG_MESSAGE -> out.decryptedData.asByteArray() to false
                TAG_FINAL -> out.decryptedData.asByteArray() to true
                else -> invalidFormat("unexpected secretstream tag")
            }
        }
    }
}
