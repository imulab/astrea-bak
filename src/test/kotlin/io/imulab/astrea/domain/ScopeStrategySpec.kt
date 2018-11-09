package io.imulab.astrea.domain

import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ScopeStrategySpec : Spek({

    infix fun String.vs(b: String): Pair<String, String> = Pair(this, b)

    describe("hierarchical strategy") {
        it("""
            fail
        """.trimIndent()) {
            listOf(
                    "book" vs "pen",
                    "book" vs "book.read",
                    "book.read" vs "book"
            ).forEach {
                assertThat(HierarchicalScopeStrategy.accepts(it.first, it.second)).isFalse()
            }
        }

        it("""
            pass
        """.trimIndent()) {
            listOf(
                    "book" vs "book",
                    "book.*" vs "book.read",
                    "book.123.*" vs "book.123.read"
            ).forEach {
                assertThat(HierarchicalScopeStrategy.accepts(it.first, it.second)).isTrue()
            }
        }
    }
})