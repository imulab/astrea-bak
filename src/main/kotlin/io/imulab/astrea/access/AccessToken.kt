package io.imulab.astrea.access

import io.imulab.astrea.oauth.OAuthRequest

data class AccessToken(val token: String,
                       val signature: String)

/**
 * Algorithms to generate and validate access token
 */
interface AccessTokenStrategy {

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