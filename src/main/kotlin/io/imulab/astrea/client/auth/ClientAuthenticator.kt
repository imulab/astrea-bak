package io.imulab.astrea.client.auth

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.spi.HttpRequestReader
import io.imulab.astrea.error.ClientAuthenticationException

/**
 * This interface authenticates a client making the HTTP request. Implementations may decide whether to use assertion
 * typed authentication or consult a truth source (i.e. database, third party service)
 */
interface ClientAuthenticator {

    /**
     * Probe method to test whether this authenticator can handle the authentication proposed by the request [reader].
     * If this method returns true, [authenticate] method should be invoked next. Otherwise, [authenticate] should not
     * be invoked.
     */
    fun supports(reader: HttpRequestReader): Boolean

    /**
     * Authenticate the client using the supplied information from [reader]. When the authentication is successful,
     * implementations must return the constructed [OAuthClient]. Otherwise, in case of authentication failure,
     * implementations must throw [ClientAuthenticationException].
     */
    fun authenticate(reader: HttpRequestReader): OAuthClient
}