package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.PasswordEncoder
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.HttpRequestReader
import io.imulab.astrea.spi.singleValue

/**
 * This implementation of [ClientAuthenticator] handles the 'client_secret_post' type authentication. The request
 * must be an HTTP POST and have client_id and client_secret set in forms in order to trigger this authenticator.
 */
class ClientSecretPostAuthenticator(private val clientManager: ClientManager,
                                    private val passwordEncoder: PasswordEncoder) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        return reader.method() == "POST" &&
                reader.formValue("client_id").isNotEmpty() &&
                reader.formValue("client_secret").isNotEmpty()
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val username = reader.formValue("client_id")
        val password = reader.formValue("client_secret")

        val client = clientManager.getClient(username)
        if (!passwordEncoder.matches(password, String(client.getHashedSecret())))
            throw ClientAuthenticationException("Invalid credentials.")

        return client
    }
}