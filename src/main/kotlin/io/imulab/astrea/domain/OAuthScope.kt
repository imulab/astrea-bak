package io.imulab.astrea.domain

/**
 * Interface that tells if one scope accepts another scope.
 */
interface OAuthScopeStrategy {
    /**
     * Returns true if scope [one] accepts scope [another]
     */
    fun accepts(one: String, another: String): Boolean
}

object StringEqualityScopeStrategy : OAuthScopeStrategy {
    override fun accepts(one: String, another: String): Boolean = one.equals(another, ignoreCase = false)
}

typealias Scope = String

fun Scope.accepts(another: Scope, strategy: OAuthScopeStrategy = StringEqualityScopeStrategy): Boolean =
        strategy.accepts(one = this, another = another)