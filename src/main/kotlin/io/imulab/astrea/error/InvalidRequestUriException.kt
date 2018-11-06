package io.imulab.astrea.error

/**
 * Thrown when the parameter value provided in `request_uri` is invalid and therefore cannot be further processed.
 */
class InvalidRequestUriException(uri: String, hint: String? = null)
    : OAuthException("invalid_request_uri", "$uri is invalid. ${hint ?: ""}".trim()) {

    override fun statusCode(): Int = 400
}