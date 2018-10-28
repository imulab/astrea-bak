package io.imulab.astrea.token.strategy

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.RefreshToken

interface RefreshTokenStrategy {

    /**
     * Returns the signature of the refresh token.
     */
    fun computeRefreshTokenSignature(token: String): String

    /**
     * Create a new refresh token, with signature computed.
     */
    fun generateNewRefreshToken(request: OAuthRequest): RefreshToken

    /**
     * Validate the provided [token].
     */
    fun validateRefreshToken(request: OAuthRequest, token: String)
}