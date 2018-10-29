package io.imulab.astrea.token.storage

/**
 * This interface provides additional capability on top of [AccessTokenStorage] and [RefreshTokenStorage] to
 * revoke/delete access token and/or refresh token by their respective request ids, which can be retrieved
 * from their stored session via the extended interfaces.
 */
interface TokenRevocationStorage : AccessTokenStorage, RefreshTokenStorage {

    /**
     * Completely delete the refresh token associated with the [requestId]. Further requests with the
     * refresh token shall fail.
     */
    fun revokeRefreshToken(requestId: String)

    /**
     * Completely delete the access token associated with the [requestId]. Further request with the
     * access token shall fail.
     */
    fun revokeAccessToken(requestId: String)
}