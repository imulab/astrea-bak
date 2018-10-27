package io.imulab.astrea.handler

import io.imulab.astrea.authorize.AuthorizeCodeStorage
import io.imulab.astrea.oauth.OAuthScopeStrategy
import io.imulab.astrea.oauth.ResponseType
import io.imulab.astrea.authorize.AuthorizeRequest
import io.imulab.astrea.authorize.AuthorizeResponse
import io.imulab.astrea.authorize.AuthorizeCodeStrategy
import io.imulab.astrea.oauth.TokenType
import io.imulab.astrea.utility.isSecureRedirectUri
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class AuthorizeFlow(
        private val scopeStrategy: OAuthScopeStrategy,
        private val authorizeCodeStrategy: AuthorizeCodeStrategy,
        private val authorizeCodeLifespan: TemporalAmount = Duration.ofMinutes(10),
        private val authorizeCodeStorage: AuthorizeCodeStorage
) : AuthorizeHandler {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (request.hasSingleCodeResponseType())
            return

        if (request.getRedirectUri()?.isSecureRedirectUri() != true)
            throw IllegalArgumentException("insecure redirect uri.")

        request.getRequestScopes().find { requestedScope ->
            request.getClient().getScopes().none { registeredScope ->
                scopeStrategy.accepts(registeredScope, requestedScope)
            }
        }.also { illegalScope ->
            if (illegalScope != null)
                throw IllegalArgumentException("scope $illegalScope cannot be accepted.")
        }

        val authCode = authorizeCodeStrategy.generateNewCode(request)
        authorizeCodeStorage.createAuthorizeCodeSession(authCode, request.also {
            it.getSession()?.setExpiry(
                    TokenType.AuthorizeCode,
                    LocalDateTime.now().plus(authorizeCodeLifespan)
            )
        })

        response.also {
            it.addQuery("code", authCode.toString())
            it.addQuery("state", request.getState())
            it.addQuery("scope", request.getGrantedScopes().joinToString(" "))
        }

        request.setResponseTypeHandled(ResponseType.Code)
    }

    private fun AuthorizeRequest.hasSingleCodeResponseType(): Boolean =
            this.getResponseTypes().size == 1 && this.getResponseTypes().contains(ResponseType.Code)
}