package io.imulab.astrea.client.auth

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.PARAM_CLIENT_ID
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.singleValue

/**
 * A no-op implementation of [ClientAuthenticator]. This implementation simply looks up the 'client_id' parameter from
 * request and construct the client. Authentication is skipped.
 */
class NoOpClientAuthenticator(private val clientManager: ClientManager) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean = true

    override fun authenticate(reader: HttpRequestReader): OAuthClient =
            clientManager.getClient(reader.getForm().singleValue(PARAM_CLIENT_ID))
}