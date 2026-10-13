// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.sync.model

import com.qtekfun.ultimateotp.core.otp.OtpParams
import kotlinx.serialization.json.JsonElement
import java.util.UUID

/**
 * One decrypted vault entry (crypto-format.md §6.1). [extra] keeps fields written by newer
 * clients so a rewrite does not drop them. Holds a secret: never log it.
 */
data class VaultItem(
    val id: UUID,
    val otp: OtpParams,
    val notes: String = "",
    val favorite: Boolean = false,
    val icon: String? = null,
    val created: Long,
    val updated: Long,
    val updatedBy: String,
    val extra: Map<String, JsonElement> = emptyMap(),
) {
    /** No secret, issuer or label: safe for logs. */
    override fun toString(): String = "VaultItem(id=$id, type=${otp.type}, updated=$updated)"

    /** Same account content, ignoring who/when it was written. */
    fun sameContent(other: VaultItem): Boolean =
        otp == other.otp && notes == other.notes && favorite == other.favorite && icon == other.icon && extra == other.extra

    companion object {
        /** `updated_by` of items written while the vault had no account. */
        const val LOCAL_DEVICE = "local"
    }
}
