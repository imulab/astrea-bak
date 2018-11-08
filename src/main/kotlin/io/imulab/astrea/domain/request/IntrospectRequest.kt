package io.imulab.astrea.domain.request

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.session.Session

/**
 * Request context for an introspection.
 */
interface IntrospectRequest {
    /**
     * Returns the token to be introspected.
     */
    fun getToken(): String

    /**
     * Returns the token type to be introspected. If not set, should return [TokenType.Unknown].
     */
    fun getTokenType(): TokenType

    /**
     * Returns the previous oauth session. If not set, returns null.
     */
    fun getSession(): Session

    /**
     * Returns the client making the request
     */
    fun getClient(): OAuthClient
}