package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.client.OpenIdConnectClient
import io.imulab.astrea.domain.AuthMethod
import io.imulab.astrea.error.ClientAuthenticationException
import io.imulab.astrea.spi.http.HttpRequestReader

/**
 * Implementation of [ClientAuthenticator] to handle none authentication method of the token endpoint.
 * This implementation only requires a *public* client specifying 'client_id' to be triggered.
 *
 * Although the pre-check is very welcoming, the actual [authenticate] checks that the client is Open ID Connect client
 * after all. So any plain OAuth client trying to use this authentication method will fail.
 *
 * **IMPORTANT**
 * This implementation gets triggered as long as there is a 'client_id' parameter. Because there is no necessary
 * authentication to be performed, the client lookup is done in the [supports] method. Therefore, if this
 * implementation is used in a chain of [ClientAuthenticator], it must be registered at the very end to let other
 * authenticators try first, sparing a data source round trip, if possible.
 */
class ClientNoneAuthenticator(private val clientManager: ClientManager) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        val clientId = reader.formValue("client_id")
        if (clientId.isEmpty())
            return false

        return try {
            val client = clientManager.getClient(clientId)
            client.isPublic()
        } catch (_: Exception) {
            false
        }
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val client = clientManager.getClient(reader.formValue("client_id"))
        if ((client is OpenIdConnectClient) && (client.getTokenEndpointAuthMethod() != AuthMethod.None))
            throw ClientAuthenticationException("Client is not capable of performing Open ID Connect none authentication.")

        return client
    }
}