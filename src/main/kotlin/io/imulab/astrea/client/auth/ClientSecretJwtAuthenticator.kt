package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.spi.HttpRequestReader

/**
 * Implementation of [ClientAuthenticator] which is supported to handle 'client_secret_jwt'. However, we decided to
 * not support this due to security reasons.
 */
class ClientSecretJwtAuthenticator(private val clientManager: ClientManager): ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        return false
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        throw UnsupportedOperationException("""
            We are not supporting this authentication mechanism because 'client_secret_jwt' requires using client
            secret as a shared HMAC SHA-256 key to sign the JWT. However, storing plain text secret or storing
            encrypted secret along with an encryption key is not safe and is therefore not support by this SDK.
        """.trimIndent())
    }
}