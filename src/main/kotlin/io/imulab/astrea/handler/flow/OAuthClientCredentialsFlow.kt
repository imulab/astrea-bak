package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.ClientGrantTypeException
import io.imulab.astrea.error.PublicClientConductingPrivateOpException
import io.imulab.astrea.error.ScopeRejectedException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class OAuthClientCredentialsFlow(
        private val scopeStrategy: ScopeStrategy,
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage,
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val refreshTokenStorage: RefreshTokenStorage
) : TokenEndpointHandler {

    override fun handleAccessRequest(request: AccessRequest): Boolean {
        if (!request.hasSingleGrantTypeOfClientCredentials())
            return false

        // check client validity
        if (request.getClient().isPublic())
            throw PublicClientConductingPrivateOpException("client credentials flow")
        else if (!request.getClient().getGrantTypes().contains(GrantType.ClientCredentials))
            throw ClientGrantTypeException(request.getClient(), GrantType.ClientCredentials)

        // check scope
        val rejectedScope = request.getRequestScopes().find { requested ->
            request.getClient().getScopes().none { registered -> scopeStrategy.accepts(registered, requested) }
        }
        if (rejectedScope != null)
            throw ScopeRejectedException(rejectedScope)

        // set expiry
        request.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.hasSingleGrantTypeOfClientCredentials())
            return false

        val accessToken = accessTokenStrategy.generateNewAccessToken(request).also {
            accessTokenStorage.createAccessTokenSession(it, request.sanitize(emptyList()))
        }

        var refreshToken: RefreshToken? = null
        if (listOf("offline", "offline_access").any { request.getGrantedScopes().contains(it) })
            refreshToken = refreshTokenStrategy.generateNewRefreshToken(request).also {
                refreshTokenStorage.createRefreshTokenSession(it, request)
            }

        response.setAccessToken(accessToken.token)
        response.setTokenType(TokenType.Bearer)
        response.setExpiry(request.getSession()!!.getExpiry(TokenType.AccessToken)!!)
        response.setScopes(request.getGrantedScopes())
        if (refreshToken != null)
            response.setExtra("refresh_token", refreshToken.token)

        return true
    }

    private fun AccessRequest.hasSingleGrantTypeOfClientCredentials(): Boolean =
            this.getGrantTypes().size == 1 && this.getGrantTypes().contains(GrantType.ClientCredentials)
}