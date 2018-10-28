package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.PasswordEncoder
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.HttpRequestReader
import java.util.*

/**
 * This implementation of [ClientAuthenticator] handles the 'client_secret_basic' type authentication. The request
 * from have HTTP Basic authentication header set in order to trigger this implementation.
 */
class ClientSecretBasicAuthenticator(private val clientManager: ClientManager,
                                     private val passwordEncoder: PasswordEncoder): ClientAuthenticator {

    private val base64Decoder = Base64.getDecoder()

    override fun supports(reader: HttpRequestReader): Boolean {
        val basicAuthHeader = reader.getHeader("Authorization")
        return basicAuthHeader.startsWith("Basic ")
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val encoded = reader.getHeader("Authorization").removePrefix("Basic ")

        var username: String?
        var password: String?
        try {
            val parts = String(base64Decoder.decode(encoded)).split(":")
            if (parts.size != 2)
                throw ClientAuthenticationException("Authorization header does not follow HTTP Basic authentication format.")
            username = parts[0]
            password = parts[1]
        } catch (e: IllegalArgumentException) {
            throw ClientAuthenticationException("Authorization header does not contain valid base64 encoded string.")
        }

        val client = clientManager.getClient(username)
        if (!passwordEncoder.matches(password, String(client.getHashedSecret())))
            throw ClientAuthenticationException("Invalid credentials.")

        return client
    }
}