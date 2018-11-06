package io.imulab.astrea.handler.impl

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.error.InvalidScopeException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAmount

class OAuthImplicitHandler(
        private val scopeStrategy: ScopeStrategy,
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage
) : AuthorizeEndpointHandler {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.getResponseTypes().exactly(ResponseType.Token))
            return

        requireNotNull(request.getSession()) { "session must not be null." }

        request.getClient().run {
            mustGrantType(GrantType.Implicit)

            getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy) { e ->
                InvalidScopeException.NotAcceptedByClient(e.scope)
            }
        }

        issueImplicitAccessToken(request, response)
    }

    fun issueImplicitAccessToken(request: AuthorizeRequest, response: AuthorizeResponse) {
        requireNotNull(request.getSession()) { "session must not be null." }

        val accessTokenExpiry = LocalDateTime.now().plus(accessTokenLifespan)

        request.getSession()!!.setExpiry(TokenType.AccessToken, accessTokenExpiry)

        val accessToken = accessTokenStrategy.generateNewAccessToken(request).also {
            accessTokenStorage.createAccessTokenSession(it, request)
        }

        response.run {
            setAccessTokenAsFragment(accessToken.token)
            setExpiresInAsFragment(LocalDateTime.now().until(accessTokenExpiry, ChronoUnit.SECONDS))
            setTokenTypeAsFragment(TokenType.Bearer)
            setStateAsFragment(request.getState())
            setScopesAsFragment(request.getGrantedScopes())
        }

        request.setResponseTypeHandled(ResponseType.Token)
    }
}