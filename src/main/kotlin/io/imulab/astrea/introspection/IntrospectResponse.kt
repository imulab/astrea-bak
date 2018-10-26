package io.imulab.astrea.introspection

import io.imulab.astrea.TokenType
import io.imulab.astrea.access.AccessRequest

/**
 * Response for an introspection.
 */
interface IntrospectResponse {
    /**
     * Returns true if the provided token is still active; false otherwise.
     */
    fun isActive(): Boolean

    /**
     * Returns the original access request, if [isActive] is true; otherwise null.
     */
    fun getAccessRequest(): AccessRequest?

    /**
     * Returns the type of the token if it can be determined. If the type
     * cannot be determined, returns [TokenType.Unknown].
     */
    fun getTokenType(): TokenType
}