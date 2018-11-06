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

typealias Scope = String
