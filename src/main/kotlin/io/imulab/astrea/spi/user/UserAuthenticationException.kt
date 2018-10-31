package io.imulab.astrea.spi.user

/**
 * Main exception thrown by [ResourceOwnerAuthenticator]. Thrown when authentication fails.
 */
class UserAuthenticationException(username: String, reason: String):
        RuntimeException("Failed to authenticate $username: $reason".removeSuffix(".").plus("."))