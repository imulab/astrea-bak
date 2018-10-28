package io.imulab.astrea.token.storage

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.token.AuthorizeCode

/**
 * Storage related to authorization codes
 */
interface AuthorizeCodeStorage {

    /**
     * Stores authorization request for given authorize code.
     */
    fun createAuthorizeCodeSession(code: AuthorizeCode, request: OAuthRequest)

    /**
     * Retrieves authorization request for given code, and also populates [session]. Implementations
     * should throw exception if the session has already been invalidated.
     */
    fun getAuthorizeCodeSession(code: AuthorizeCode, session: Session): OAuthRequest

    /**
     * Invalidates the stored session identified by [code]. It should be called when the [code] is used.
     */
    fun invalidateAuthorizeCodeSession(code: AuthorizeCode)
}