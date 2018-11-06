package io.imulab.astrea.error

/**
 * invalid_request_object
 *
 * The request parameter contains an invalid Request Object.
 */
class InvalidRequestObjectException(reason: String) : OAuthException("invalid_request_object", reason) {

    override fun statusCode(): Int = 400
}