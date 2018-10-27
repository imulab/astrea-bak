package io.imulab.astrea.authorize

import io.imulab.astrea.oauth.OAuthRequest

/**
 * Authorize code. Use [toString] to get final code.
 */
data class AuthorizeCode(val token: String,
                         val signature: String) {
    companion object {
        fun fromCode(code: String): AuthorizeCode {
            val parts = code.split(".")
            if (parts.size != 2)
                throw IllegalArgumentException("invalid code format. code must be of format \"\$token.\$signature\".")
            return AuthorizeCode(token = parts[0], signature = parts[1])
        }
    }

    override fun toString(): String = "$token.$signature"
}

/**
 * Algorithms to generate and validate authorize code
 */
interface AuthorizeCodeStrategy {

    /**
     * Returns the signature of the authorization code. Typically used to
     * identify the code from storage.
     */
    fun computeCodeSignature(code: String): String

    /**
     * Create a new authorization code, with signature computed.
     */
    fun generateNewCode(request: OAuthRequest): AuthorizeCode

    /**
     * Validate the provided [code].
     */
    fun validateCode(request: OAuthRequest, code: String)
}