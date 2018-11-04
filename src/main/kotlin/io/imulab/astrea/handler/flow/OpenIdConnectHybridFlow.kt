package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.storage.AuthorizeCodeStorage
import io.imulab.astrea.token.storage.OpenIdConnectRequestStorage
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.IdTokenStrategy

class OpenIdConnectHybridFlow(
        private val openIdConnectAuthorizeCodeFlow: OpenIdConnectAuthorizeCodeFlow,
        private val oAuthImplicitFlow: OAuthImplicitFlow,
        private val authorizeCodeStrategy: AuthorizeCodeStrategy,
        private val authorizeCodeStorage: AuthorizeCodeStorage,
        private val authorizeCodeSafeStorageParameters: List<String> = listOf("code", "redirect_uri"),
        private val openIdConnectTokenStrategy: IdTokenStrategy,
        private val openIdConnectRequestValidator: OpenIdConnectRequestValidator,
        private val openIdConnectRequestStorage: OpenIdConnectRequestStorage,
        private val scopeStrategy: ScopeStrategy,
        private val minimumNonceEntropy: Int = 8,
        private val openIdConnectSafeStorageParameters: List<String> = listOf(
                PARAM_GRANT_TYPE,
                PARAM_MAX_AGE,
                PARAM_PROMPT,
                PARAM_ACR_VALUE,
                PARAM_ID_TOKEN_HINT,
                PARAM_NONCE
        )
) : AuthorizeEndpointHandler, TokenEndpointHandler by openIdConnectAuthorizeCodeFlow {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.shouldHandle())
            return

        with(request.getNonce()) {
            if (this.isEmpty())
                throw IllegalArgumentException("nonce required.")
            else if (this.length < minimumNonceEntropy)
                throw IllegalArgumentException("nonce must be at least $minimumNonceEntropy in length.")
        }

        request.getClient().getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy)

        openIdConnectRequestValidator.validateRequest(request)

        val oidcSession = request.getSession().assertType<OidcSession>()

        if (request.getResponseTypes().contains(ResponseType.Code)) {
            request.getClient().mustGrantType(GrantType.AuthorizationCode)

            val authorizeCode = authorizeCodeStrategy.generateNewAuthorizeCode(request).also {
                authorizeCodeStorage.createAuthorizeCodeSession(it, request.sanitize(authorizeCodeSafeStorageParameters))
            }

            response.setCodeAsFragment(authorizeCode.code)
            request.setResponseTypeHandled(ResponseType.Code)

            response.getCode()
                    .let { openIdConnectTokenStrategy.leftMostHash(it) }
                    .let { oidcSession.getIdTokenClaims().setCodeHash(it) }

            if (request.getGrantedScopes().contains(SCOPE_OPENID))
                openIdConnectRequestStorage.createOidcSession(
                        authorizeCode,
                        request.sanitize(openIdConnectSafeStorageParameters)
                )
        }

        if (request.getResponseTypes().contains(ResponseType.Token)) {
            request.getClient().mustGrantType(GrantType.Implicit)

            oAuthImplicitFlow.issueImplicitAccessToken(request, response)
            request.setResponseTypeHandled(ResponseType.Token)

            response.getAccessTokenFromFragment()
                    .let { openIdConnectTokenStrategy.leftMostHash(it) }
                    .let { oidcSession.getIdTokenClaims().setAccessTokenHash(it) }
        }

        if (response.getStateFromFragment().isEmpty())
            response.setStateAsFragment(request.getState())

        if (request.getGrantedScopes().contains(SCOPE_OPENID) &&
                request.getResponseTypes().contains(ResponseType.IdToken))
            response.setIdTokenAsFragment(openIdConnectTokenStrategy.generateIdToken(request).token)

        request.setResponseTypeHandled(ResponseType.IdToken)
    }

    private fun AuthorizeRequest.shouldHandle(): Boolean {
        return when (this.getResponseTypes().size) {
            2 -> this.getResponseTypes().containsAll(listOf(ResponseType.Token, ResponseType.Code)) ||
                    this.getResponseTypes().containsAll(listOf(ResponseType.IdToken, ResponseType.Code))
            3 -> this.getResponseTypes().containsAll(listOf(ResponseType.Token, ResponseType.Code, ResponseType.IdToken))
            else -> false
        }
    }
}