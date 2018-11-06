package io.imulab.astrea.domain.extension

import io.imulab.astrea.domain.Scope
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.error.InvalidScopeException

/**
 * A reverse implementation of [mustAcceptAll] to allow fluent execution.
 */
fun Collection<Scope>.mustAllBeAcceptedBy(
        scopes: Collection<Scope>,
        strategy: ScopeStrategy = StringEqualityScopeStrategy,
        exceptionEnhancer: ((InvalidScopeException) -> Throwable)? = null
): Collection<Scope> {
    scopes.mustAcceptAll(this, strategy, exceptionEnhancer)
    return this
}

fun Scope.accepts(another: Scope, strategy: ScopeStrategy = StringEqualityScopeStrategy): Boolean =
        strategy.accepts(one = this, another = another)

/**
 * Enforce the scope collection represented by [this] to accept all scopes in collection [scopes]. The acceptance strategy
 * is provided by [strategy], which defaults to [StringEqualityScopeStrategy].
 *
 * If any scope is not accepted, this method throws [InvalidScopeException] with the rejected scope set. Caller can provide
 * an [exceptionEnhancer] to provide more error context.
 *
 * If all scope is accepted, it returns [this].
 */
fun Collection<Scope>.mustAcceptAll(
        scopes: Collection<Scope>,
        strategy: ScopeStrategy = StringEqualityScopeStrategy,
        exceptionEnhancer: ((InvalidScopeException) -> Throwable)? = null
): Collection<Scope> {
    val rejected = scopes.find { test -> this.none { registered -> strategy.accepts(registered, test) } }
    if (rejected != null)
        throw InvalidScopeException(rejected).let {
            if (exceptionEnhancer != null)
                exceptionEnhancer(it)
            else
                it
        }
    return this
}

fun Collection<Scope>.containsAny(vararg scopes: Scope): Boolean =
        scopes.any { this.contains(it) }

fun Collection<Scope>.containsNone(vararg scopes: Scope): Boolean =
        !this.containsAny(*scopes)