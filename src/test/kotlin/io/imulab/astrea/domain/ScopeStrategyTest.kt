package io.imulab.astrea.domain

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

class ScopeStrategyTest {

    companion object {
        @JvmStatic
        fun hierarchicalTestSource() = listOf(
                Arguments.of("book", "book", true),
                Arguments.of("book", "pen", false),
                Arguments.of("book", "book.read", false),
                Arguments.of("book.*", "book.read", true),
                Arguments.of("book.read", "book", false),
                Arguments.of("book.123.*", "book.123.read", true)
        )
    }

    @ParameterizedTest
    @MethodSource("hierarchicalTestSource")
    fun testHierarchicalStrategy(truth: String, test: String, expect: Boolean) {
        Assertions.assertEquals(expect, HierarchicalScopeStrategy.accepts(truth, test))
    }
}