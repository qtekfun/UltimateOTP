// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.testguard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.lang.reflect.Method

/**
 * Compiled into the test source set of every module by the convention plugins (the file lives in
 * `android/config/testguard`). It exists because of a failure that stayed invisible for a while:
 * JUnit 5 does not run a `@Test` method that returns a value, and says nothing about it. A Kotlin
 * expression body (`fun x() = runBlocking { ... }`) returns the value of its last expression, so
 * three tests passed in every run without ever executing.
 *
 * It scans the compiled test classes of the module it runs in and fails on:
 * - a test method (JUnit 5 `@Test`, `@ParameterizedTest`, `@RepeatedTest`, `@TestTemplate`,
 *   JUnit 4 `@Test`) whose return type is not `void` (`Unit`): it would be skipped silently;
 * - a disabled test (`@Disabled`, `@Ignore`) whose reason does not start with `KNOWN BUG`: a
 *   skipped test must name the defect it is waiting for and is listed in docs/testing.md.
 */
class TestMethodsReturnUnitTest {
    @Test
    fun `every test method of this module returns Unit and none is silently disabled`() {
        val source: java.net.URL? =
            TestMethodsReturnUnitTest::class.java.protectionDomain
                ?.codeSource
                ?.location
        val here = File(requireNotNull(source) { "no code source for the guard class" }.toURI())
        assertTrue(here.isDirectory, "expected the test classes directory, got $here")
        val classes =
            here
                .walkTopDown()
                .filter { it.extension == "class" }
                .map {
                    it
                        .relativeTo(here)
                        .path
                        .removeSuffix(".class")
                        .replace(File.separatorChar, '.')
                }.filterNot { it.startsWith("META-INF") }
                .mapNotNull { name -> runCatching { Class.forName(name, false, javaClass.classLoader) }.getOrNull() }
                .toList()
        val found = TestGuard.testMethods(classes).count()
        val problems = TestGuard.violations(classes)
        assertEquals(emptyList<String>(), problems, "tests that would be skipped, or disabled without a known bug")
        // A scan that finds nothing would pass for the wrong reason (moved directory, renamed annotation).
        assertTrue(found > 1, "the guard found $found test methods in $here: the scan is broken")
    }

    @Test
    fun `the guard itself flags a value-returning test and a bare disabled test`() {
        val fake = setOf(FakeTest::class.java.name)
        val methods = TestGuard.violations(listOf(Sample::class.java), fake, setOf(FakeDisabled::class.java.name))
        assertEquals(3, methods.size, methods.toString())
        assertTrue(methods.any { "returnsAValue" in it && "returns" in it })
        assertTrue(methods.any { "returnsLong" in it })
        assertTrue(methods.any { "disabledWithoutBug" in it })
        assertTrue(methods.none { "fine" in it || "disabledForKnownBug" in it })
    }

    private annotation class FakeTest

    private annotation class FakeDisabled(
        val value: String = "",
    )

    @Suppress("unused")
    private class Sample {
        @FakeTest fun fine() {}

        @FakeTest fun returnsAValue() = listOf(1)

        @FakeTest fun returnsLong(): Long = 1

        @FakeTest
        @FakeDisabled("flaky")
        fun disabledWithoutBug() {}

        @FakeTest
        @FakeDisabled("KNOWN BUG KB-9: waits for a fix")
        fun disabledForKnownBug() {}

        fun helperMayReturn() = 1
    }
}

internal object TestGuard {
    val TEST_ANNOTATIONS =
        setOf(
            "org.junit.jupiter.api.Test",
            "org.junit.jupiter.params.ParameterizedTest",
            "org.junit.jupiter.api.RepeatedTest",
            "org.junit.jupiter.api.TestTemplate",
            "org.junit.Test",
        )
    val DISABLED_ANNOTATIONS = setOf("org.junit.jupiter.api.Disabled", "org.junit.Ignore")

    fun testMethods(
        classes: List<Class<*>>,
        testAnnotations: Set<String> = TEST_ANNOTATIONS,
    ): Sequence<Method> =
        classes
            .asSequence()
            .flatMap { runCatching { it.declaredMethods.asSequence() }.getOrDefault(emptySequence()) }
            .filter { m -> m.annotations.any { it.annotationClass.java.name in testAnnotations } }

    fun violations(
        classes: List<Class<*>>,
        testAnnotations: Set<String> = TEST_ANNOTATIONS,
        disabledAnnotations: Set<String> = DISABLED_ANNOTATIONS,
    ): List<String> =
        testMethods(classes, testAnnotations)
            .flatMap { m ->
                val where = "${m.declaringClass.name}.${m.name}"
                val problems = mutableListOf<String>()
                if (m.returnType != Void.TYPE) {
                    problems += "$where returns ${m.returnType.simpleName}: JUnit skips it silently (declare `: Unit`)"
                }
                m.annotations
                    .filter { it.annotationClass.java.name in disabledAnnotations }
                    .forEach { a ->
                        val reason = reasonOf(a)
                        if (!reason.startsWith("KNOWN BUG")) problems += "$where is disabled without a KNOWN BUG reason ('$reason')"
                    }
                problems.asSequence()
            }.toList()

    private fun reasonOf(annotation: Annotation): String =
        runCatching {
            annotation.annotationClass.java
                .getMethod("value")
                .invoke(annotation) as? String
        }.getOrNull().orEmpty()
}
