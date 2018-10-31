package io.imulab.astrea.spi.user

/**
 * Service provider interface for authenticating an resource owner, used mainly by resource owner password flow.
 */
interface ResourceOwnerAuthenticator {

    /**
     * Perform authentication using the given [username] and plain text [password]. For best security, implementations
     * should not send unprocessed [password] to remote system.
     */
    fun authenticate(username: String, password: String)
}