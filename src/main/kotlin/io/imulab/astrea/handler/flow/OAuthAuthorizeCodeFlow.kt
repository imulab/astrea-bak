package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.error.ClientIdentityMismatchException
import io.imulab.astrea.error.MissingSessionException
import io.imulab.astrea.error.RedirectUriMismatchException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.storage.AuthorizeCodeStorage
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import java.time.Duration
import java.time.LocalDateTime
import java.time.temporal.TemporalAmount

class OAuthAuthorizeCodeFlow(
        private val scopeStrategy: ScopeStrategy,
        private val authorizeCodeStrategy: AuthorizeCodeStrategy,
        private val authorizeCodeLifespan: TemporalAmount = Duration.ofMinutes(10),
        private val authorizeCodeStorage: AuthorizeCodeStorage,
        private val safeStorageParameters: List<String> = listOf("code", "redirect_uri"),
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage,
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val refreshTokenStorage: RefreshTokenStorage
) : AuthorizeEndpointHandler, TokenEndpointHandler {

    // start: AuthorizeEndpointHandler ---------------------------------------------------------------------------------

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.hasSingleResponseTypeOf(ResponseType.Code))
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

        val authCode = authorizeCodeStrategy.generateNewAuthorizeCode(request)
        authorizeCodeStorage.createAuthorizeCodeSession(authCode, request.also {
            it.getSession()?.setExpiry(
                    TokenType.AuthorizeCode,
                    LocalDateTime.now().plus(authorizeCodeLifespan)
            )
        }.sanitize(safeStorageParameters))

        response.also {
            it.addQuery("code", authCode.code)
            it.addQuery("state", request.getState())
            it.addQuery("scope", request.getGrantedScopes().joinToString(" "))
        }

        request.setResponseTypeHandled(ResponseType.Code)
    }

    // end: AuthorizeEndpointHandler -----------------------------------------------------------------------------------

    // start: TokenEndpointHandler -------------------------------------------------------------------------------------

    override fun handleAccessRequest(request: AccessRequest): Boolean {
        if (!request.hasSingleGrantTypeOf(GrantType.AuthorizationCode))
            return false

        request.getClient().mustGrantType(GrantType.AuthorizationCode)

        if (request.getSession() == null)
            throw MissingSessionException()

        // retrieve authorization code from session storage
        val authorizeCode = AuthorizeCode.fromRaw(request.getRequestForm().singleValue("code"))
        val authorizeRequest = authorizeCodeStorage.getAuthorizeCodeSession(authorizeCode, request.getSession()!!)

        // validate code
        // ?? use 'request' or 'authorizeRequest'
        authorizeCodeStrategy.validateAuthorizeCode(authorizeRequest, authorizeCode.code)

        // Override request scopes to ensure no rewrite
        request.setRequestScopes(authorizeRequest.getRequestScopes())

        // Compare and match the identity of the client making the request with the one restored from session.
        if (authorizeRequest.getClient().getId() != request.getClient().getId())
            throw ClientIdentityMismatchException(authorizeRequest.getClient(), request.getClient())

        // Compare and match the redirect URI to prevent any malicious redirection.
        val restoredRedirectUri = authorizeRequest.getRequestForm().singleValue("redirect_uri")
        val presentedRedirectUri = request.getRequestForm().singleValue("redirect_uri")
        if (restoredRedirectUri.isNotBlank() && restoredRedirectUri != presentedRedirectUri)
            throw RedirectUriMismatchException(restoredRedirectUri, presentedRedirectUri)

        request.let {
            it.setSession(authorizeRequest.getSession()!!)
            it.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))
            it.setId(authorizeRequest.getId())
        }

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.hasSingleGrantTypeOf(GrantType.AuthorizationCode))
            return false

        // retrieve authorization code from session storage
        val authorizeCode = AuthorizeCode.fromRaw(request.getRequestForm().singleValue("code"))
        val authorizeRequest = authorizeCodeStorage.getAuthorizeCodeSession(authorizeCode, request.getSession()!!)

        // transfer grants of scopes
        authorizeRequest.getGrantedScopes().forEach(request::grantScope)

        // generate tokens
        val accessToken = accessTokenStrategy.generateNewAccessToken(request)
        var refreshToken: RefreshToken? = null
        if (listOf("offline", "offline_access").any(authorizeRequest.getGrantedScopes()::contains))
            refreshToken = refreshTokenStrategy.generateNewRefreshToken(request)

        // deal with sessions
        authorizeCodeStorage.invalidateAuthorizeCodeSession(authorizeCode)
        accessTokenStorage.createAccessTokenSession(accessToken, request.sanitize(emptyList()))
        if (refreshToken != null)
            refreshTokenStorage.createRefreshTokenSession(refreshToken, request.sanitize(emptyList()))

        response.also {
            it.setAccessToken(accessToken.token)
            it.setTokenType(TokenType.Bearer)
            it.setExpiry(request.getSession()!!.getExpiry(TokenType.AccessToken)!!)
            it.setScopes(request.getGrantedScopes())
            if (refreshToken != null)
                it.setExtra("refresh_token", refreshToken.token)
        }

        return true
    }

    // end: TokenEndpointHandler ---------------------------------------------------------------------------------------
}