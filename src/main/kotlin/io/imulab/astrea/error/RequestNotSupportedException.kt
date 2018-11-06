package io.imulab.astrea.error

/**
 * Thrown when the OP does not support use of the request parameter defined in Section 6.
 */
class RequestNotSupportedException(reason: String) : OAuthException("request_not_supported", reason)