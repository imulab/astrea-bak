package io.imulab.astrea.authorize

import io.imulab.astrea.oauth.OAuthRequest

/**
 * Algorithms to generate and validate authorize code
 */
interface AuthorizeCodeStrategy {

    /**
     * Returns the signature of the authorization code. Typically used to
     * identify the code from storage.
     */
    fun computeAuthorizeCodeSignature(code: String): String

    /**
     * Create a new authorization code, with signature computed.
     */
    fun generateNewAuthorizeCode(request: OAuthRequest): AuthorizeCode

    /**
     * Validate the provided [code].
     */
    fun validateAuthorizeCode(request: OAuthRequest, code: String)
}