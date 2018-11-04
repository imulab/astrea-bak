package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.error.ClientIdentityMismatchException
import io.imulab.astrea.error.MissingSessionException
import io.imulab.astrea.error.RedirectUriMismatchException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
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
        private val safeStorageParameters: List<String> = listOf(PARAM_CODE, PARAM_REDIRECT_URI),
        private val accessTokenLifespan: TemporalAmount = Duration.ofMinutes(30),
        private val accessTokenStrategy: AccessTokenStrategy,
        private val accessTokenStorage: AccessTokenStorage,
        private val refreshTokenStrategy: RefreshTokenStrategy,
        private val refreshTokenStorage: RefreshTokenStorage
) : AuthorizeEndpointHandler, TokenEndpointHandler {

    // start: AuthorizeEndpointHandler ---------------------------------------------------------------------------------

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.getResponseTypes().exactly(ResponseType.Code))
            return

        if (request.getRedirectUri()?.isSecureRedirectUri() != true)
            throw IllegalArgumentException("insecure redirect uri.")

        request.getClient().getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy)

        val authCode = authorizeCodeStrategy.generateNewAuthorizeCode(request)
        authorizeCodeStorage.createAuthorizeCodeSession(authCode, request.also {
            it.getSession()?.setExpiry(
                    TokenType.AuthorizeCode,
                    LocalDateTime.now().plus(authorizeCodeLifespan)
            )
        }.sanitize(safeStorageParameters))

        response.run {
            setCodeAsQuery(authCode.code)
            setStateAsQuery(request.getState())
            setScopesAsQuery(request.getGrantedScopes())
        }

        request.setResponseTypeHandled(ResponseType.Code)
    }

    // end: AuthorizeEndpointHandler -----------------------------------------------------------------------------------

    // start: TokenEndpointHandler -------------------------------------------------------------------------------------

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.AuthorizationCode)

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        request.getClient().mustGrantType(GrantType.AuthorizationCode)

        if (request.getSession() == null)
            throw MissingSessionException()

        // retrieve authorization code from session storage
        val authorizeCode = authorizeCodeStrategy.fromRaw(request.getCode())
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
        val restoredRedirectUri = authorizeRequest.getRedirectUri()
        val presentedRedirectUri = request.getRedirectUri()
        if (restoredRedirectUri.isNotBlank() && restoredRedirectUri != presentedRedirectUri)
            throw RedirectUriMismatchException(restoredRedirectUri, presentedRedirectUri)

        request.let {
            it.setSession(authorizeRequest.getSession()!!)
            it.getSession()!!.setExpiry(TokenType.AccessToken, LocalDateTime.now().plus(accessTokenLifespan))
            it.setId(authorizeRequest.getId())
        }
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

        // retrieve authorization code from session storage
        val authorizeCode = authorizeCodeStrategy.fromRaw(request.getCode())
        val authorizeRequest = authorizeCodeStorage.getAuthorizeCodeSession(authorizeCode, request.getSession()!!)

        // transfer grants of scopes
        authorizeRequest.getGrantedScopes().forEach(request::grantScope)

        // generate tokens
        val accessToken = accessTokenStrategy.generateNewAccessToken(request)
        var refreshToken: RefreshToken? = null
        if (authorizeRequest.getGrantedScopes().containsAny(SCOPE_OFFLINE, SCOPE_OFFLINE_ACCESS))
            refreshToken = refreshTokenStrategy.generateNewRefreshToken(request)

        // deal with sessions
        authorizeCodeStorage.invalidateAuthorizeCodeSession(authorizeCode)
        accessTokenStorage.createAccessTokenSession(accessToken, request.sanitize(emptyList()))
        if (refreshToken != null)
            refreshTokenStorage.createRefreshTokenSession(refreshToken, request.sanitize(emptyList()))

        response.run {
            setAccessToken(accessToken.token)
            setTokenType(TokenType.Bearer)
            setExpiry(request.getSession()!!.getExpiry(TokenType.AccessToken)!!)
            setScopes(request.getGrantedScopes())
            if (refreshToken != null)
                setRefreshToken(refreshToken.token)
        }
    }

    // end: TokenEndpointHandler ---------------------------------------------------------------------------------------
}