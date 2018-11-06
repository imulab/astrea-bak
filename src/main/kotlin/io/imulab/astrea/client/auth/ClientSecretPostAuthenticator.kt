package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.crypt.PasswordEncoder
import io.imulab.astrea.domain.AuthMethod
import io.imulab.astrea.domain.PARAM_CLIENT_ID
import io.imulab.astrea.domain.PARAM_CLIENT_SECRET
import io.imulab.astrea.domain.extension.requireNotNullOrEmpty
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.mustSingleValue
import io.imulab.astrea.spi.http.singleValue

/**
 * This implementation of [ClientAuthenticator] handles the 'client_secret_post' type authentication. The request
 * must be an HTTP POST and have client_id and client_secret set in forms in order to trigger this authenticator.
 */
class ClientSecretPostAuthenticator(private val clientManager: ClientManager,
                                    private val passwordEncoder: PasswordEncoder) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        return reader.method() == "POST" &&
                reader.getForm().singleValue(PARAM_CLIENT_ID).isNotEmpty() &&
                reader.getForm().singleValue(PARAM_CLIENT_SECRET).isNotEmpty()
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val username = reader.getForm().mustSingleValue(PARAM_CLIENT_ID).requireNotNullOrEmpty(PARAM_CLIENT_ID)
        val password = reader.getForm().mustSingleValue(PARAM_CLIENT_SECRET).requireNotNullOrEmpty(PARAM_CLIENT_SECRET)

        val client = clientManager.getClient(username)
        if ((client is OpenIdConnectClient) && (client.getTokenEndpointAuthMethod() != AuthMethod.ClientSecretPost))
            throw InvalidClientException.IncapableOfAuthMethod(AuthMethod.ClientSecretPost)

        if (!passwordEncoder.matches(password, String(client.getHashedSecret())))
            throw InvalidClientException.AuthenticationFailed("Invalid credentials.")

        return client
    }
}