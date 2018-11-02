package io.imulab.astrea.token.storage

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.AuthorizeCode

/**
 * Storage related to Open ID Connect session.
 */
interface OpenIdConnectRequestStorage {

    /**
     * Stores OIDC request for the given [authorizeCode].
     */
    fun createOidcSession(authorizeCode: AuthorizeCode, request: OAuthRequest)

    /**
     * Retrieve OIDC request given [authorizeCode].
     */
    fun getOidcSession(authorizeCode: AuthorizeCode, request: OAuthRequest): OAuthRequest

    /**
     * Delete the OIDC request session associated with the [authorizeCode].
     */
    fun deleteOidcSession(authorizeCode: AuthorizeCode)
}