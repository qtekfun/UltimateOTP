// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.icons

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class IssuerIconsTest {
    @Test
    fun `spellings of one issuer find the same icon`() {
        listOf("GitHub", "Github", "github", "github.com", "GitHub Inc.", "gist.github.com", "GITHUB", " GitHub ").forEach {
            assertEquals("github", IssuerIcons.keyFor(it), it)
        }
        assertEquals("google", IssuerIcons.keyFor("Google LLC"))
        assertEquals("google", IssuerIcons.keyFor("accounts.google.com"))
        assertEquals("google", IssuerIcons.keyFor("Google Account"))
    }

    @Test
    fun `aliases and renamed brands`() {
        assertEquals("x", IssuerIcons.keyFor("Twitter"))
        assertEquals("x", IssuerIcons.keyFor("X Corp."))
        assertEquals("facebook", IssuerIcons.keyFor("Meta"))
        assertEquals("digitalocean", IssuerIcons.keyFor("Digital Ocean"))
        assertEquals("npm", IssuerIcons.keyFor("npmjs.com"))
        assertEquals("protonmail", IssuerIcons.keyFor("Proton Mail"))
        assertEquals("blockchaindotcom", IssuerIcons.keyFor("Blockchain.com"))
        assertEquals("1password", IssuerIcons.keyFor("1Password"))
    }

    @Test
    fun `self hosted instances match by their service label`() {
        assertEquals("gitlab", IssuerIcons.keyFor("gitlab.mycompany.com"))
        assertEquals("nextcloud", IssuerIcons.keyFor("nextcloud.example.org"))
    }

    @Test
    fun `unknown and ambiguous names do not match`() {
        assertNull(IssuerIcons.keyFor(""))
        assertNull(IssuerIcons.keyFor("Some Tiny Startup"))
        assertNull(IssuerIcons.keyFor("fosstodon.org"))
        assertNull(IssuerIcons.keyFor("X-Ray Labs"))
    }

    @Test
    fun `first word matches a longer name`() {
        assertEquals("steam", IssuerIcons.keyFor("Steam Community"))
        assertEquals("cloudflare", IssuerIcons.keyFor("Cloudflare Dashboard"))
    }

    @Test
    fun `brands without a bundled mark get a letter on the brand colour`() {
        val ms = IssuerIcons.visualFor("Microsoft")
        assertTrue(ms is IssuerVisual.Letter && ms.brand)
        val aws = IssuerIcons.visualFor("Amazon Web Services")
        assertTrue(aws is IssuerVisual.Letter && aws.brand)
    }

    @Test
    fun `visual prefers the explicit key then the issuer then the label prefix`() {
        assertTrue(IssuerIcons.visualFor("Whatever", iconKey = "github") is IssuerVisual.Brand)
        assertTrue(IssuerIcons.visualFor("GitHub") is IssuerVisual.Brand)
        assertTrue(IssuerIcons.visualFor("", "GitHub:me@example.org") is IssuerVisual.Brand)
    }

    @Test
    fun `letter avatar is stable and depends only on the name`() {
        val a = IssuerIcons.visualFor("Acme Intranet") as IssuerVisual.Letter
        val b = IssuerIcons.visualFor("acme  intranet") as IssuerVisual.Letter
        assertEquals("A", a.letter)
        assertEquals(a.argb, b.argb)
        // Pinned values: they must not change between releases or devices.
        assertEquals(0xFF5B5FC7.toInt(), IssuerIcons.letterColor("Acme Intranet"))
        assertEquals("?", IssuerIcons.initial("  "))
        assertNotEquals(IssuerIcons.letterColor("alpha"), IssuerIcons.letterColor("omega") + 1)
    }

    @Test
    fun `every bundled icon has a drawable and a brand colour`() {
        assertTrue(SIMPLE_ICONS.size >= 150)
        SIMPLE_ICONS.forEach { (slug, icon) ->
            assertTrue(icon.drawable != 0, slug)
            assertTrue(icon.brand in 0..0xFFFFFF, slug)
            assertEquals(slug, IssuerIcons.keyFor(slug), slug)
        }
    }
}
