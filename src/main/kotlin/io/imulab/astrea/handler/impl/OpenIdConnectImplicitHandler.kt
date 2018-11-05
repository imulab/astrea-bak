package io.imulab.astrea.handler.impl

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.strategy.IdTokenStrategy

class OpenIdConnectImplicitHandler(
        private val oauthImplicitHandler: OAuthImplicitHandler,
        private val scopeStrategy: ScopeStrategy,
        private val openIdConnectTokenStrategy: IdTokenStrategy,
        private val openIdConnectRequestValidator: OpenIdConnectRequestValidator,
        private val minimumNonceEntropy: Int = 8
) : AuthorizeEndpointHandler {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.shouldHandle())
            return

        request.getClient().mustGrantType(GrantType.Implicit)

        with(request.getNonce()) {
            if (isEmpty())
                throw IllegalArgumentException("nonce required.")
            else if (length < minimumNonceEntropy)
                throw IllegalArgumentException("nonce must be at least $minimumNonceEntropy in length.")
        }

        request.getClient().getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy)

        openIdConnectRequestValidator.validateRequest(request)

        val oidcSession = request.getSession().assertType<OidcSession>()

        if (request.getResponseTypes().contains(ResponseType.Token)) {
            oauthImplicitHandler.issueImplicitAccessToken(request, response)

            response.getAccessTokenFromFragment()
                    .let { openIdConnectTokenStrategy.leftMostHash(it) }
                    .let { oidcSession.getIdTokenClaims().setAccessTokenHash(it) }
        } else {
            response.setStateAsFragment(request.getState())
        }

        response.setIdTokenAsFragment(openIdConnectTokenStrategy.generateIdToken(request).token)

        request.setResponseTypeHandled(ResponseType.IdToken)
    }

    private fun AuthorizeRequest.shouldHandle(): Boolean {
        return when {
            getResponseTypes().exactly(ResponseType.IdToken) -> true
            getResponseTypes().containsAll(listOf(ResponseType.Token, ResponseType.IdToken)) &&
                    getGrantedScopes().contains(SCOPE_OPENID) -> true
            !getResponseTypes().contains(ResponseType.Code) -> true
            else -> false
        }
    }
}