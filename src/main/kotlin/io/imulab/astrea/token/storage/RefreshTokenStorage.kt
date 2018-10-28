package io.imulab.astrea.token.storage

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.OAuthSession
import io.imulab.astrea.token.RefreshToken

/**
 * Storage related to refresh token.
 */
interface RefreshTokenStorage {

    /**
     * Stores access request for the given [RefreshToken].
     */
    fun createRefreshTokenSession(token: RefreshToken, request: OAuthRequest)

    /**
     * Retrieves refresh token request for [token]. [OAuthRequest.getSession] should be populated.
     */
    fun getRefreshTokenSession(token: RefreshToken, session: OAuthSession): OAuthRequest

    /**
     * Removes information related to the refresh [token].
     */
    fun deleteRefreshTokenSession(token: RefreshToken)
}