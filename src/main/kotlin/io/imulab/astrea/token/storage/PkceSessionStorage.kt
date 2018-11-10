package io.imulab.astrea.token.storage

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.AuthorizeCode

/**
 * Storage to maintain public client PKCE session state. This storage is a function enhancement in addition to
 * [io.imulab.astrea.token.storage.AuthorizeCodeStorage]
 */
interface PkceSessionStorage {

    /**
     * Returns a [OAuthRequest] if it was associated with the authorizeCode. This storage will only
     * check for existence, as expiration and other checks should have been performed by an upstream
     * [io.imulab.astrea.token.storage.AuthorizeCodeStorage] when chained.
     *
     * @throws [io.imulab.astrea.error.InvalidGrantException.NotFound] if not found
     */
    fun getPkceSession(authorizeCode: AuthorizeCode): OAuthRequest

    /**
     * Associates the given [authorizeCode] with the [request]. The saved [request] needs to be
     * [OAuthRequest.sanitize] first.
     */
    fun createPkceSession(authorizeCode: AuthorizeCode, request: OAuthRequest)

    /**
     * Removes the associated [OAuthRequest] by [authorizeCode]
     */
    fun deletePkceSession(authorizeCode: AuthorizeCode)
}