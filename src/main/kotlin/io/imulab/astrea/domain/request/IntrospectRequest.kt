package io.imulab.astrea.domain.request

import io.imulab.astrea.domain.Scope
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.session.Session

/**
 * Request context for an introspection.
 */
interface IntrospectRequest {
    /**
     * Set the requested token to be introspected.
     */
    fun setToken(token: String)

    /**
     * Returns the token to be introspected.
     */
    fun getToken(): String

    /**
     * Set the token type to be introspected.
     */
    fun setTokenType(type: TokenType)

    /**
     * Returns the token type to be introspected. If not set, should return [TokenType.Unknown].
     */
    fun getTokenType(): TokenType

    /**
     * Returns the previous oauth session. If not set, returns null.
     */
    fun getSession(): Session?

    /**
     * Set the previous oauth session.
     */
    fun setSession(session: Session)

    /**
     * Returns the list of scopes. If not set, should return empty list.
     */
    fun getScopes(): List<Scope>

    /**
     * Add a scope.
     */
    fun addScope(scope: Scope)
}