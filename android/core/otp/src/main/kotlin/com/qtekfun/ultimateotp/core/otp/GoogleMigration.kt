// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.otp

import java.util.Base64

/**
 * Google Authenticator's export QR codes: `otpauth-migration://offline?data=<base64 protobuf>`.
 * The protobuf (`MigrationPayload`, field 1 = repeated `OtpParameters`) is small enough to read
 * by hand, so no protobuf runtime is needed.
 */
object GoogleMigration {
    const val SCHEME = "otpauth-migration://"

    private const val WIRE_VARINT = 0
    private const val WIRE_64BIT = 1
    private const val WIRE_LENGTH = 2
    private const val WIRE_32BIT = 5
    private const val FIELD_SHIFT = 3
    private const val WIRE_MASK = 0x7
    private const val VARINT_PAYLOAD = 0x7F
    private const val VARINT_CONTINUE = 0x80
    private const val VARINT_STEP = 7
    private const val MAX_VARINT_SHIFT = 63
    private const val BYTE_MASK = 0xFF

    private const val F_OTP_PARAMETERS = 1
    private const val F_SECRET = 1
    private const val F_NAME = 2
    private const val F_ISSUER = 3
    private const val F_ALGORITHM = 4
    private const val F_DIGITS = 5
    private const val F_TYPE = 6
    private const val F_COUNTER = 7

    private const val ALG_SHA256 = 2L
    private const val ALG_SHA512 = 3L
    private const val ALG_MD5 = 4L
    private const val DIGITS_EIGHT = 2L
    private const val EIGHT = 8
    private const val TYPE_HOTP = 1L

    /** @throws OtpUriException if the URI or its payload is malformed. */
    fun parse(uri: String): List<OtpParams> {
        val data = uri.substringAfter("data=", "").substringBefore('&')
        if (data.isEmpty()) throw OtpUriException("Missing migration data")
        val bytes =
            try {
                Base64.getDecoder().decode(OtpAuthUri.decode(data, plusIsSpace = false).replace(' ', '+'))
            } catch (e: IllegalArgumentException) {
                throw OtpUriException("Migration data is not base64", e)
            }
        return fields(bytes).mapNotNull { f -> f.bytes?.takeIf { f.number == F_OTP_PARAMETERS }?.let(::account) }
    }

    private fun account(bytes: ByteArray): OtpParams {
        var secret: ByteArray? = null
        var name = ""
        var issuer = ""
        var algorithm = OtpAlgorithm.SHA1
        var digits = OtpParams.DEFAULT_DIGITS
        var hotp = false
        var counter = 0L
        for (f in fields(bytes)) {
            when (f.number) {
                F_SECRET -> secret = f.bytes
                F_NAME -> name = text(f)
                F_ISSUER -> issuer = text(f)
                F_ALGORITHM -> algorithm = algorithmOf(f.value)
                F_DIGITS -> digits = if (f.value == DIGITS_EIGHT) EIGHT else OtpParams.DEFAULT_DIGITS
                F_TYPE -> hotp = f.value == TYPE_HOTP
                F_COUNTER -> counter = f.value
            }
        }
        val key = secret?.takeIf { it.isNotEmpty() } ?: throw OtpUriException("Missing secret")
        val label = if (issuer.isNotEmpty() && name.startsWith("$issuer:")) name.substring(issuer.length + 1) else name
        return OtpParams(
            type = if (hotp) OtpType.HOTP else OtpType.TOTP,
            secret = key,
            algorithm = algorithm,
            digits = digits,
            counter = counter,
            issuer = issuer.ifEmpty { name.substringBefore(':', "") },
            label = label.trim(),
        )
    }

    private fun algorithmOf(value: Long): OtpAlgorithm =
        when (value) {
            ALG_SHA256 -> OtpAlgorithm.SHA256
            ALG_SHA512 -> OtpAlgorithm.SHA512
            ALG_MD5 -> throw OtpUriException("MD5 accounts are not supported")
            else -> OtpAlgorithm.SHA1
        }

    private fun malformed(): Nothing = throw OtpUriException("Malformed migration data")

    private fun text(f: Field): String = f.bytes?.toString(Charsets.UTF_8).orEmpty()

    private class Field(
        val number: Int,
        val value: Long,
        val bytes: ByteArray?,
    )

    private fun fields(data: ByteArray): List<Field> {
        val reader = ProtoReader(data)
        val out = mutableListOf<Field>()
        while (reader.hasMore()) reader.next()?.let(out::add)
        return out
    }

    /** Minimal protobuf wire-format reader; every overrun is reported as malformed data. */
    private class ProtoReader(
        private val data: ByteArray,
    ) {
        private var pos = 0

        fun hasMore(): Boolean = pos < data.size

        fun varint(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                if (pos >= data.size || shift > MAX_VARINT_SHIFT) malformed()
                val b = data[pos++].toInt() and BYTE_MASK
                result = result or ((b and VARINT_PAYLOAD).toLong() shl shift)
                if (b and VARINT_CONTINUE == 0) return result
                shift += VARINT_STEP
            }
        }

        /** The next field, or null for fixed-width fields we do not need. */
        fun next(): Field? {
            val key = varint()
            val number = (key ushr FIELD_SHIFT).toInt()
            return when ((key and WIRE_MASK.toLong()).toInt()) {
                WIRE_VARINT -> Field(number, varint(), null)
                WIRE_LENGTH -> Field(number, 0, take(varint()))
                WIRE_64BIT -> null.also { take(Long.SIZE_BYTES.toLong()) }
                WIRE_32BIT -> null.also { take(Int.SIZE_BYTES.toLong()) }
                else -> malformed()
            }
        }

        private fun take(length: Long): ByteArray {
            if (length < 0 || length > data.size - pos) malformed()
            return data.copyOfRange(pos, pos + length.toInt()).also { pos += length.toInt() }
        }
    }
}
