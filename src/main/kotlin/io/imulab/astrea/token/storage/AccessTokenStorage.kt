package io.imulab.astrea.token.storage

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.AccessToken

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
    fun getAccessTokenSession(token: AccessToken): OAuthRequest

    /**
     * Removes information related to the access [token].
     */
    fun deleteAccessTokenSession(token: AccessToken)
}