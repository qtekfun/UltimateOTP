// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import com.qtekfun.ultimateotp.core.otp.Base32
import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.util.UUID

/** Thrown for an item plaintext this client cannot use. No content in the message. */
class ItemFormatException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/** The item plaintext JSON of crypto-format.md §6.1. */
object ItemCodec {
    const val VERSION = 1
    private val KNOWN =
        setOf(
            "v",
            "type",
            "secret",
            "algorithm",
            "digits",
            "period",
            "counter",
            "issuer",
            "label",
            "icon",
            "tags",
            "notes",
            "favorite",
            "created",
            "updated",
            "updated_by",
        )

    fun encode(item: VaultItem): ByteArray {
        val otp = item.otp
        val fields = linkedMapOf<String, JsonElement>()
        fields.putAll(item.extra.filterKeys { it !in KNOWN })
        fields["v"] = JsonPrimitive(VERSION)
        fields["type"] = JsonPrimitive(otp.type.uriName)
        fields["secret"] = JsonPrimitive(Base32.encode(otp.secret))
        fields["algorithm"] = JsonPrimitive(otp.algorithm.name)
        fields["digits"] = JsonPrimitive(otp.digits)
        if (otp.type == OtpType.HOTP) fields["counter"] = JsonPrimitive(otp.counter) else fields["period"] = JsonPrimitive(otp.period)
        fields["issuer"] = JsonPrimitive(otp.issuer)
        fields["label"] = JsonPrimitive(otp.label)
        fields["icon"] = item.icon?.let(::JsonPrimitive) ?: JsonNull
        fields["tags"] = JsonArray(otp.tags.map(::JsonPrimitive))
        fields["notes"] = JsonPrimitive(item.notes)
        fields["favorite"] = JsonPrimitive(item.favorite)
        fields["created"] = JsonPrimitive(item.created)
        fields["updated"] = JsonPrimitive(item.updated)
        fields["updated_by"] = JsonPrimitive(item.updatedBy)
        return JsonObject(fields).toString().toByteArray(Charsets.UTF_8)
    }

    fun decode(
        id: UUID,
        plaintext: ByteArray,
    ): VaultItem =
        try {
            val o = Json.parseToJsonElement(String(plaintext, Charsets.UTF_8)).jsonObject
            val type = OtpType.entries.firstOrNull { it.uriName == o.str("type") } ?: fail("unknown type")
            val otp =
                OtpParams(
                    type = type,
                    secret = Base32.decode(o.str("secret") ?: fail("missing secret")),
                    algorithm = OtpAlgorithm.parse(o.str("algorithm")) ?: OtpAlgorithm.SHA1,
                    digits = o.int("digits") ?: OtpParams.DEFAULT_DIGITS,
                    period = o.int("period") ?: OtpParams.DEFAULT_PERIOD,
                    counter = o.long("counter") ?: 0,
                    issuer = o.str("issuer").orEmpty(),
                    label = o.str("label").orEmpty(),
                    tags = o["tags"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull }.orEmpty(),
                )
            VaultItem(
                id = id,
                otp = otp,
                notes = o.str("notes").orEmpty(),
                favorite = o["favorite"]?.jsonPrimitive?.booleanOrNull ?: false,
                icon = o.str("icon"),
                created = o.long("created") ?: 0,
                updated = o.long("updated") ?: 0,
                updatedBy = o.str("updated_by").orEmpty(),
                extra = o.filterKeys { it !in KNOWN },
            )
        } catch (e: IllegalArgumentException) {
            throw ItemFormatException("unreadable item", e)
        }

    private fun fail(message: String): Nothing = throw ItemFormatException(message)

    private fun JsonObject.str(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.int(name: String): Int? = (this[name] as? JsonPrimitive)?.intOrNull

    private fun JsonObject.long(name: String): Long? = (this[name] as? JsonPrimitive)?.longOrNull
}
