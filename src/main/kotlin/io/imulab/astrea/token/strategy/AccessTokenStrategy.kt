package io.imulab.astrea.token.strategy

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.AccessToken

/**
 * Algorithms to generate and validate access token
 */
interface AccessTokenStrategy {

    /**
     * Parses the [raw] representation of access token and return as an [AccessToken] object.
     */
    fun fromRaw(raw: String): AccessToken

    /**
     * Returns the signature of the access token.
     */
    fun computeAccessTokenSignature(token: String): String

    /**
     * Create a new access token, with signature computed.
     */
    fun generateNewAccessToken(request: OAuthRequest): AccessToken

    /**
     * Validate the provided [token].
     */
    fun validateAccessToken(request: OAuthRequest, token: String)
}