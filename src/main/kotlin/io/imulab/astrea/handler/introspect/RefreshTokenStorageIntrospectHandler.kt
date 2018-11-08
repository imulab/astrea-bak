package io.imulab.astrea.handler.introspect

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.response.impl.DefaultIntrospectResponse
import io.imulab.astrea.handler.IntrospectEndpointHandler
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.strategy.RefreshTokenStrategy

/**
 * Implementation of [IntrospectEndpointHandler] that reads access token information from [RefreshTokenStorage].
 */
class RefreshTokenStorageIntrospectHandler(
        private val refreshTokenStorage: RefreshTokenStorage,
        private val refreshTokenStrategy: RefreshTokenStrategy
) : IntrospectEndpointHandler {

    override fun inspects(): Collection<TokenType> = listOf(TokenType.RefreshToken)

    override fun introspectToken(request: IntrospectRequest): IntrospectResponse {
        return try {
            val r = refreshTokenStrategy.fromRaw(request.getToken()).let {
                refreshTokenStorage.getRefreshTokenSession(it, request.getSession())
            } as AccessRequest

            refreshTokenStrategy.validateRefreshToken(r, request.getToken())

            DefaultIntrospectResponse(active = true, accessRequest = r, tokenType = TokenType.RefreshToken)
        } catch (_: Exception) {
            DefaultIntrospectResponse(active = false)
        }
    }
}