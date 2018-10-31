package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.PasswordEncoder
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.http.HttpRequestReader

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

    companion object {

        /**
         * Returns a default chain of [ClientAuthenticator]. In most cases, this is sufficient.
         */
        fun defaultChain(clientManager: ClientManager,
                         passwordEncoder: PasswordEncoder,
                         tokenEndpointUrl: String): ClientAuthenticator =
                ClientAuthenticatorChain(listOf(
                        ClientSecretBasicAuthenticator(clientManager, passwordEncoder),
                        ClientSecretPostAuthenticator(clientManager, passwordEncoder),
                        ClientPrivateKeyJwtAuthenticator(clientManager, tokenEndpointUrl),
                        ClientSecretJwtAuthenticator(),
                        ClientNoneAuthenticator(clientManager)
                ))

        /**
         * Returns a custom chain of [ClientAuthenticator].
         */
        fun customChain(vararg clientAuthenticators: ClientAuthenticator): ClientAuthenticator =
                ClientAuthenticatorChain(clientAuthenticators.toList())
    }

    private class ClientAuthenticatorChain(private val chain: List<ClientAuthenticator>) : ClientAuthenticator {

        override fun supports(reader: HttpRequestReader): Boolean = true

        override fun authenticate(reader: HttpRequestReader): OAuthClient {
            for (authenticator in chain) {
                if (authenticator.supports(reader))
                    return authenticator.authenticate(reader)
            }
            throw ClientAuthenticationException("Nothing can authenticate the client.")
        }
    }
}