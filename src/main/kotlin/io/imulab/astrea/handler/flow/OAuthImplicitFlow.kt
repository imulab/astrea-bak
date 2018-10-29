package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.error.ClientGrantTypeException
import io.imulab.astrea.error.ScopeRejectedException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAmount

class OAuthImplicitFlow(
        private val scopeStrategy: ScopeStrategy,
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage
) : AuthorizeEndpointHandler {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.hasSingleResponseTypeOfToken())
            return

        if (!request.getClient().getGrantTypes().contains(GrantType.Implicit))
            throw ClientGrantTypeException(request.getClient(), GrantType.Implicit)

        val rejectedScope = request.getRequestScopes().find { requested ->
            request.getClient().getScopes().none { registered -> scopeStrategy.accepts(registered, requested) }
        }
        if (rejectedScope != null)
            throw ScopeRejectedException(rejectedScope)

        val accessTokenExpiry = LocalDateTime.now().plus(accessTokenLifespan)
        request.getSession()!!.setExpiry(TokenType.AccessToken, accessTokenExpiry)

        val accessToken = accessTokenStrategy.generateNewAccessToken(request).also {
            accessTokenStorage.createAccessTokenSession(it, request)
        }

        response.also {
            it.addFragment("access_token", accessToken.token)
            it.addFragment("expires_in", LocalDateTime.now().until(accessTokenExpiry, ChronoUnit.SECONDS).toString())
            it.addFragment("token_type", TokenType.Bearer.specValue)
            it.addFragment("state", request.getState())
            it.addFragment("scope", request.getGrantedScopes().joinToString(" "))
        }

        request.setResponseTypeHandled(ResponseType.Token)
    }

    private fun AuthorizeRequest.hasSingleResponseTypeOfToken(): Boolean =
            this.getResponseTypes().size == 1 && this.getResponseTypes().contains(ResponseType.Token)
}