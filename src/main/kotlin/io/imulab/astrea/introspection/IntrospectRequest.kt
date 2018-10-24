package io.imulab.astrea.introspection

import io.imulab.astrea.OAuthSession
import io.imulab.astrea.Scope
import io.imulab.astrea.TokenType

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
    fun getSession(): OAuthSession?

    /**
     * Set the previous oauth session.
     */
    fun setSession(session: OAuthSession)

    /**
     * Returns the list of scopes. If not set, should return empty list.
     */
    fun getScopes(): List<Scope>

    /**
     * Add a scope.
     */
    fun addScope(scope: Scope)
}