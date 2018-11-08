package io.imulab.astrea.domain.request

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.TokenType

interface RevocationRequest {

    /**
     * Returns the token to be revoked.
     */
    fun getToken(): String

    /**
     * Returns the token type to be revoked. If not set, should return [TokenType.Unknown].
     * This should just serve as a hint.
     */
    fun getTokenType(): TokenType

    /**
     * Returns the client making the request
     */
    fun getClient(): OAuthClient
}