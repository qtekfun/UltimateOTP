// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.screenshots

import com.qtekfun.ultimateotp.core.otp.OtpAlgorithm
import com.qtekfun.ultimateotp.core.otp.OtpParams
import com.qtekfun.ultimateotp.core.otp.OtpType
import com.qtekfun.ultimateotp.core.sync.DeviceView
import com.qtekfun.ultimateotp.core.sync.api.SessionInfo
import com.qtekfun.ultimateotp.core.sync.model.VaultItem
import java.util.UUID

/** Fake accounts and devices for the screenshots; the secrets are made up. */
object Fixtures {
    /** A fixed clock: 27 s into a 30 s period, so the next-code preview and the red ring show. */
    const val NOW = 1_700_000_040_000L + 27_000L

    private fun item(
        n: Int,
        issuer: String,
        label: String,
        tags: List<String> = emptyList(),
        pinned: Boolean = false,
        type: OtpType = OtpType.TOTP,
        period: Int = 30,
        digits: Int = 6,
        notes: String = "",
    ) = VaultItem(
        id = UUID(0L, n.toLong()),
        otp =
            OtpParams(
                type = type,
                secret = ByteArray(10) { (it * 7 + n).toByte() },
                algorithm = OtpAlgorithm.SHA1,
                digits = if (type == OtpType.STEAM) OtpParams.STEAM_DIGITS else digits,
                period = period,
                issuer = issuer,
                label = label,
                tags = tags,
            ),
        notes = notes,
        favorite = pinned,
        created = 0,
        updated = 0,
        updatedBy = VaultItem.LOCAL_DEVICE,
    )

    val items: List<VaultItem> =
        listOf(
            item(1, "GitHub", "alice@example.org", tags = listOf("Work", "Dev"), pinned = true),
            item(2, "Google", "alice@gmail.com", tags = listOf("Personal"), pinned = true),
            item(3, "Proton", "alice@proton.me", tags = listOf("Personal")),
            item(4, "Cloudflare", "ops@example.org", tags = listOf("Work")),
            item(5, "Steam", "alice_games", type = OtpType.STEAM),
            item(6, "Amazon Web Services", "root-account", tags = listOf("Work"), digits = 8),
            item(7, "Nextcloud", "alice@cloud.example.org", tags = listOf("Personal"), period = 60),
            item(8, "Acme Intranet", "a.smith", type = OtpType.HOTP, notes = "Counter based token from the helpdesk"),
            item(9, "Bitwarden", "alice@example.org"),
            item(10, "Hetzner", "alice"),
        )

    val devices: List<DeviceView> =
        listOf(
            DeviceView("d1", "Pixel 9 Pro Fold", trusted = true, revoked = false, isThisDevice = true),
            DeviceView("d2", "Galaxy S24", trusted = true, revoked = false, isThisDevice = false),
            DeviceView("d3", "Pixel 6a", trusted = false, revoked = false, isThisDevice = false),
            DeviceView("d4", "Old tablet", trusted = true, revoked = true, isThisDevice = false),
        )

    val sessions: Map<String, SessionInfo> =
        mapOf(
            "d1" to SessionInfo("d1", "Pixel 9 Pro Fold", "0.2.0", "signup", 1_690_000_000, 1_700_000_000, "203.0.113.7", current = true),
            "d2" to SessionInfo("d2", "Galaxy S24", "0.2.0", "login", 1_690_000_000, 1_699_900_000, "198.51.100.23"),
            "d3" to SessionInfo("d3", "Pixel 6a", "0.1.2", "login", 1_690_000_000, 1_699_000_000, "192.0.2.80"),
            "d4" to
                SessionInfo("d4", "Old tablet", "0.1.0", "pairing", 1_600_000_000, 1_650_000_000, "192.0.2.5", revokedAt = 1_660_000_000),
        )

    val words: List<String> =
        (
            "abandon ability able about above absent absorb abstract absurd abuse access accident " +
                "account accuse achieve acid acoustic acquire across act action actor actress actual"
        ).split(' ')
}
