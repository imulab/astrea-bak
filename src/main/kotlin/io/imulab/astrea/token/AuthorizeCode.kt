package io.imulab.astrea.token

/**
 * Authorize code.
 */
data class AuthorizeCode(val code: String,
                         val signature: String) {
    companion object {
    }
}

