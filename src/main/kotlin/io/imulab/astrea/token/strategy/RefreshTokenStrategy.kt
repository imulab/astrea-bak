package io.imulab.astrea.token.strategy

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.RefreshToken

interface RefreshTokenStrategy {

    /**
     * Parses the [raw] representation of refresh token and return as an [RefreshToken] object.
     */
    fun fromRaw(raw: String): RefreshToken

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