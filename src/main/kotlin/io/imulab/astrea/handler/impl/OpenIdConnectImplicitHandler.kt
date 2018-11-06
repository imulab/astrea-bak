package io.imulab.astrea.handler.impl

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.error.InvalidScopeException
import io.imulab.astrea.error.RequestParameterInvalidValueException
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

        requireNotNull(request.getSession()) { "session must not be null" }

        request.getClient().mustGrantType(GrantType.Implicit)

        with(request.getNonce()) {
            requireNotNullOrEmpty(PARAM_NONCE)

            if (length < minimumNonceEntropy)
                throw RequestParameterInvalidValueException.NonceInsufficientEntropy(this, minimumNonceEntropy)
        }

        request.getClient().getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy) { e ->
            InvalidScopeException.NotAcceptedByClient(e.scope)
        }

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
        val idTokenOrPlusTokenResponseType =
                getResponseTypes().exactly(ResponseType.IdToken) ||
                        getResponseTypes().containsAll(listOf(ResponseType.Token, ResponseType.IdToken))

        return when {
            !(getGrantedScopes().contains(SCOPE_OPENID) && idTokenOrPlusTokenResponseType) -> false
            getResponseTypes().contains(ResponseType.Code) -> false
            else -> true
        }
    }
}