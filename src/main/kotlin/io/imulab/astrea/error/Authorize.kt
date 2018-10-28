package io.imulab.astrea.error

/**
 * Thrown when the provided authorize cannot be verified.
 */
class InvalidAuthorizeCodeException(code: String, reason: String) :
        RuntimeException("authorize code \"$code\" is invalid: $reason")