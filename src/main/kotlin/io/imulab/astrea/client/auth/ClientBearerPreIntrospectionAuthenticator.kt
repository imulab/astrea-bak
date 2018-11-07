package io.imulab.astrea.client.auth

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import java.lang.Exception

/**
 * This authenticator will introspect the access token provided with the request to introspect the
 * client's identity.
 */
class ClientBearerPreIntrospectionAuthenticator(
        private val accessTokenStorage: AccessTokenStorage,
        private val accessTokenStrategy: AccessTokenStrategy
) : ClientAuthenticator {

    override fun supports(reader: HttpRequestReader): Boolean {
        val basicAuthHeader = reader.getHeader("Authorization")
        return basicAuthHeader.startsWith("Bearer ")
    }

    override fun authenticate(reader: HttpRequestReader): OAuthClient {
        val accessToken = reader.getHeader("Authorization").removePrefix("Bearer ").trim()
        val introspectToken = reader.getForm().singleValue(PARAM_TOKEN)
        if (accessToken == introspectToken)
            throw InvalidClientException.AuthenticationFailed("access token and introspect token cannot be the same one.")

        return try {
            accessToken.let { accessTokenStrategy.fromRaw(it) }
                    .let { accessTokenStorage.getAccessTokenSession(it, DefaultSession()) }
                    .getClient()
        } catch (e: Exception) {
            throw InvalidClientException.AuthenticationFailed(e.message ?: "")
        }
    }
}