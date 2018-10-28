package io.imulab.astrea.token

import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.error.TokenInvalidity

/**
 * Authorize code.
 */
data class AuthorizeCode(val code: String,
                         val signature: String) {
    companion object {
        fun fromRaw(raw: String): AuthorizeCode {
            val parts = raw.split(".")
            if (parts.size != 2)
                throw InvalidAuthorizeCodeException(TokenInvalidity.BadFormat)
            return AuthorizeCode(code = raw, signature = parts[1])
        }
    }
}

