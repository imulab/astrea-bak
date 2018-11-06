package io.imulab.astrea.domain

/**
 * Interface that tells if one scope accepts another scope.
 */
interface ScopeStrategy {
    /**
     * Returns true if scope [one] accepts scope [another]
     */
    fun accepts(one: String, another: String): Boolean
}

object StringEqualityScopeStrategy : ScopeStrategy {
    override fun accepts(one: String, another: String): Boolean = one.equals(another, ignoreCase = false)
}

object HierarchicalScopeStrategy : ScopeStrategy {
    override fun accepts(one: String, another: String): Boolean {
        if (StringEqualityScopeStrategy.accepts(one, another))
            return true

        val truthComponents = one.split(DOT)
        val testComponents = another.split(DOT)

        // truth is more specific
        if (truthComponents.size > testComponents.size)
            return false

        truthComponents.forEachIndexed { index, s ->
            when (s) {
                // undecided, depends on components behind
                testComponents[index] -> return@forEachIndexed
                // truth accepts everything
                "*" -> return true
                // fail
                else -> return false
            }
        }

        // did not accept by having a '*'
        // fail if testComponents is more specific (greater length)
        // e.g. 'book' cannot accept 'book.read'
        return testComponents.size == truthComponents.size
    }
}

typealias Scope = String
