package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.containsAny
import io.imulab.astrea.domain.extension.mustAcceptAll
import io.imulab.astrea.domain.extension.setRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.error.InvalidScopeException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class OAuthClientCredentialsHandler(
        private val scopeStrategy: ScopeStrategy,
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage,
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val refreshTokenStorage: RefreshTokenStorage
) : TokenEndpointHandler {

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.ClientCredentials)

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null." }

        request.getClient().run {
            if (isPublic())
                throw InvalidClientException.PublicClient()

            mustGrantType(GrantType.ClientCredentials)

            getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy) { e ->
                InvalidScopeException.NotAcceptedByClient(e.scope)
            }
        }

        // set expiry
        request.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null." }

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