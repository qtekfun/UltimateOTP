// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/** Every translatable string of `values/` exists in each `values-xx/` with the same placeholders. */
class StringsParityTest {
    private val res = File("src/main/res")
    private val placeholder = Regex("%(\\d+\\$)?[sdf]|%%")

    /** name to the sorted placeholders of every item (plurals: one entry per quantity). */
    private fun parse(file: File): Map<String, List<List<String>>> {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val out = mutableMapOf<String, List<List<String>>>()
        val root = doc.documentElement
        val nodes = (0 until root.childNodes.length).mapNotNull { root.childNodes.item(it) as? Element }
        for (node in nodes.filter { it.getAttribute("translatable") != "false" }) {
            val name = node.getAttribute("name")
            when (node.tagName) {
                "string" -> {
                    out[name] = listOf(placeholders(node.textContent))
                }

                "plurals" -> {
                    val items = node.getElementsByTagName("item")
                    out[name] = (0 until items.length).map { placeholders(items.item(it).textContent) }
                }
            }
        }
        return out
    }

    private fun placeholders(text: String): List<String> =
        placeholder
            .findAll(text)
            .map { it.value }
            .sorted()
            .toList()

    private fun translations(): List<File> =
        res
            .listFiles { f ->
                f.isDirectory && f.name.startsWith("values-")
            }.orEmpty()
            .map { File(it, "strings.xml") }
            .filter { it.exists() }

    @Test
    fun `there is at least one translation`() {
        assertTrue(translations().any { it.parentFile?.name == "values-es" })
    }

    @Test
    fun `every string is translated with the same placeholders`() {
        val default = parse(File(res, "values/strings.xml"))
        translations().forEach { file ->
            val translated = parse(file)
            val where = file.parentFile?.name.orEmpty()
            assertEquals(default.keys.sorted(), translated.keys.sorted(), "$where: missing or extra keys")
            default.forEach { (name, items) ->
                val other = translated.getValue(name)
                val expected = items.first()
                other.forEach { assertEquals(expected, it, "$where: placeholders of $name") }
                assertTrue(items.all { it == expected }, "default $name items differ")
            }
        }
    }

    @Test
    fun `positional placeholders are used when there are several`() {
        parse(File(res, "values/strings.xml")).forEach { (name, items) ->
            items.forEach { list ->
                if (list.size > 1) assertTrue(list.all { it.contains('$') }, "$name must use %1\$s style placeholders")
            }
        }
    }
}
