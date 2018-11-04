package io.imulab.astrea.token

import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.error.TokenInvalidity

/**
 * Authorize code.
 */
data class AuthorizeCode(val code: String,
                         val signature: String) {
    companion object {
    }
}

