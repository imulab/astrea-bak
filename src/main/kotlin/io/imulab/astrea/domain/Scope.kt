package io.imulab.astrea.domain

import io.imulab.astrea.error.ScopeRejectedException

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

fun Scope.accepts(another: Scope, strategy: ScopeStrategy = StringEqualityScopeStrategy): Boolean =
        strategy.accepts(one = this, another = another)

fun List<Scope>.mustAcceptAll(scopes: Collection<Scope>, strategy: ScopeStrategy = StringEqualityScopeStrategy) {
    val rejected = scopes.find { test -> this.none{ registered -> strategy.accepts(registered, test) } }
    if (rejected != null)
        throw ScopeRejectedException(rejected)
}