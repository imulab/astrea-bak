package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.PublicClientConductingPrivateOpException
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
        if (!request.getGrantTypes().exactly(GrantType.ClientCredentials))
            return false

        // check client validity
        if (request.getClient().isPublic())
            throw PublicClientConductingPrivateOpException("client credentials flow")
        request.getClient().mustGrantType(GrantType.ClientCredentials)

        // check scope
        request.getClient().getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy)

        // set expiry
        request.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.getGrantTypes().exactly(GrantType.ClientCredentials))
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
}