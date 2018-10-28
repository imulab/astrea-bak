package io.imulab.astrea.domain.response

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest

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