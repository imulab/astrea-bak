package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getPassword
import io.imulab.astrea.domain.extension.getUsername
import io.imulab.astrea.domain.extension.removePassword
import io.imulab.astrea.domain.extension.setRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.spi.user.ResourceOwnerAuthenticator
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class OAuthResourceOwnerFlow(
        private val scopeStrategy: ScopeStrategy,
        private val resourceOwnerAuthenticator: ResourceOwnerAuthenticator,
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage,
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val refreshTokenStorage: RefreshTokenStorage
) : TokenEndpointHandler {

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.Password)

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        request.getClient().run {
            mustGrantType(GrantType.Password)
            getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy)
        }

        // authenticate user
        val username = request.getUsername()
        val password = request.getPassword()
        if (username.isBlank() || password.isBlank())
            throw IllegalArgumentException("username or password not provided.")
        resourceOwnerAuthenticator.authenticate(username, password)

        // clear password so we don't accidentally save it
        request.removePassword()

        // set access token expiry
        request.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

        val accessToken = accessTokenStrategy.generateNewAccessToken(request).also {
            accessTokenStorage.createAccessTokenSession(it, request.sanitize(emptyList()))
        }

        var refreshToken: RefreshToken? = null
        if (request.getGrantedScopes().containsAny(SCOPE_OFFLINE, SCOPE_OFFLINE_ACCESS))
            refreshToken = refreshTokenStrategy.generateNewRefreshToken(request).also {
                refreshTokenStorage.createRefreshTokenSession(it, request)
            }

        response.run {
            setAccessToken(accessToken.token)
            setTokenType(TokenType.Bearer)
            setExpiry(request.getSession()!!.getExpiry(TokenType.AccessToken)!!)
            setScopes(request.getGrantedScopes())
            if (refreshToken != null)
                setRefreshToken(refreshToken.token)
        }
    }
}