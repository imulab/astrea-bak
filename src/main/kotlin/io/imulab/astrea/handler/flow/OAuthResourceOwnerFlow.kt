package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.ClientGrantTypeException
import io.imulab.astrea.error.ScopeRejectedException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.spi.http.delete
import io.imulab.astrea.spi.http.singleValue
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

    override fun handleAccessRequest(request: AccessRequest): Boolean {
        if (!request.hasSingleGrantTypeOf(GrantType.Password))
            return false

        // check grant type
        if (!request.getClient().getGrantTypes().contains(GrantType.Password))
            throw ClientGrantTypeException(request.getClient(), GrantType.Password)

        // check scope
        val rejectedScope = request.getRequestScopes().find { requested ->
            request.getClient().getScopes().none { registered -> scopeStrategy.accepts(registered, requested) }
        }
        if (rejectedScope != null)
            throw ScopeRejectedException(rejectedScope)

        // authenticate user
        val username = request.getRequestForm().singleValue("username")
        val password = request.getRequestForm().singleValue("password")
        if (username.isBlank() || password.isBlank())
            throw IllegalArgumentException("username or password not provided.")
        else
            resourceOwnerAuthenticator.authenticate(username, password)

        // clear password so we don't accidentally save it
        request.getRequestForm().delete("password")

        // set access token expiry
        request.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.hasSingleGrantTypeOf(GrantType.Password))
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