package io.imulab.astrea.error

import io.imulab.astrea.domain.Scope

/**
 * invalid_scope
 *
 * The requested scope is invalid, unknown, malformed, or
 * exceeds the scope granted by the resource owner.
 */
open class InvalidScopeException(val scope: Scope, hint: String? = null)
    : OAuthException("invalid_scope", "Scope '$scope' is invalid. ${hint ?: ""}".trim()) {

    override fun statusCode(): Int = 400

    class NotAcceptedByClient(scope: Scope) : InvalidScopeException(scope, "Client does not accept such scope.") {
        override fun statusCode(): Int = 401
    }

    class NotGrantedByResourceOwner(scope: Scope) : InvalidScopeException(scope, "Resource owner did not grant such scope.") {
        override fun statusCode(): Int = 401
    }
}