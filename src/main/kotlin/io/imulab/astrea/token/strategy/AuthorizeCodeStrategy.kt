package io.imulab.astrea.token.strategy

import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.token.AuthorizeCode

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