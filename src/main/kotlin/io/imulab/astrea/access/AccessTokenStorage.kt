package io.imulab.astrea.access

import io.imulab.astrea.oauth.OAuthRequest
import io.imulab.astrea.oauth.OAuthSession

/**
 * Storage related to access token.
 */
interface AccessTokenStorage {

    /**
     * Stores access request for the given [AccessToken].
     */
    fun createAccessTokenSession(token: AccessToken, request: OAuthRequest)

    /**
     * Retrieves access token request for [token]. [OAuthRequest.getSession] should be populated.
     */
    fun getAccessTokenSession(token: AccessToken, session: OAuthSession): OAuthRequest

    /**
     * Removes information related to the access [token].
     */
    fun deleteAccessTokenSession(token: AccessToken)
}