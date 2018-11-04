package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.crypt.PasswordEncoder
import io.imulab.astrea.domain.AuthMethod
import io.imulab.astrea.domain.PARAM_CLIENT_ID
import io.imulab.astrea.domain.PARAM_CLIENT_SECRET
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.http.HttpRequestReader

/**
 * This implementation of [ClientAuthenticator] handles the 'client_secret_post' type authentication. The request
 * must be an HTTP POST and have client_id and client_secret set in forms in order to trigger this authenticator.
 */
class ClientSecretPostAuthenticator(private val clientManager: ClientManager,
                                    private val passwordEncoder: PasswordEncoder) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        return reader.method() == "POST" &&
                reader.formValue(PARAM_CLIENT_ID).isNotEmpty() &&
                reader.formValue(PARAM_CLIENT_SECRET).isNotEmpty()
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val username = reader.formValue(PARAM_CLIENT_ID)
        val password = reader.formValue(PARAM_CLIENT_SECRET)

        val client = clientManager.getClient(username)
        if ((client is OpenIdConnectClient) && (client.getTokenEndpointAuthMethod() != AuthMethod.ClientSecretPost))
            throw ClientAuthenticationException("Client is not capable of performing Open ID Connect client_secret_post authentication.")

        if (!passwordEncoder.matches(password, String(client.getHashedSecret())))
            throw ClientAuthenticationException("Invalid credentials.")

        return client
    }
}