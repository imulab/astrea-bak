package io.imulab.astrea.handler.introspect

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.response.impl.DefaultIntrospectResponse
import io.imulab.astrea.handler.IntrospectEndpointHandler
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy

/**
 * Implementation of [IntrospectEndpointHandler] that reads access token information from [AccessTokenStorage].
 */
class AccessTokenStorageIntrospectHandler(
        private val accessTokenStorage: AccessTokenStorage,
        private val accessTokenStrategy: AccessTokenStrategy
) : IntrospectEndpointHandler {

    override fun inspects(): Collection<TokenType> = listOf(TokenType.AccessToken)

    override fun introspectToken(request: IntrospectRequest): IntrospectResponse {
        return try {
            val r = accessTokenStrategy.fromRaw(request.getToken()).let {
                accessTokenStorage.getAccessTokenSession(it, request.getSession())
            } as AccessRequest

            accessTokenStrategy.validateAccessToken(r, request.getToken())

            DefaultIntrospectResponse(active = true, accessRequest = r, tokenType = TokenType.AccessToken)
        } catch (_: Exception) {
            DefaultIntrospectResponse(active = false)
        }
    }
}