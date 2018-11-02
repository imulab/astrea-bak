package io.imulab.astrea.token.storage

import io.imulab.astrea.domain.request.OAuthRequest

/**
 * Storage related to Open ID Connect session.
 */
interface OpenIdConnectRequestStorage {

    /**
     * Stores OIDC request for the given [authorizeCode].
     */
    fun createOidcSession(authorizeCode: String, request: OAuthRequest)

    /**
     * Retrieve OIDC request given [authorizeCode].
     */
    fun getOidcSession(authorizeCode: String, request: OAuthRequest): OAuthRequest

    /**
     * Delete the OIDC request session associated with the [authorizeCode].
     */
    fun deleteOidcSession(authorizeCode: String)
}