package io.imulab.astrea.access

import io.imulab.astrea.oauth.OAuthRequest
import io.imulab.astrea.oauth.OAuthSession

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