package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.strategy.IdTokenStrategy

class OpenIdConnectImplicitFlow(
        private val oauthImplicitFlow: OAuthImplicitFlow,
        private val scopeStrategy: ScopeStrategy,
        private val openIdConnectTokenStrategy: IdTokenStrategy,
        private val openIdConnectRequestValidator: OpenIdConnectRequestValidator,
        private val minimumNonceEntropy: Int = 8
) : AuthorizeEndpointHandler {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.shouldHandle())
            return

        request.getClient().mustGrantType(GrantType.Implicit)

        request.getRequestForm().singleValue("nonce").also {
            if (it.isEmpty())
                throw IllegalArgumentException("nonce required.")
            else if (it.length < minimumNonceEntropy)
                throw IllegalArgumentException("nonce must be at least $minimumNonceEntropy in length.")
        }

        request.getClient().getScopes().mustAcceptAll(request.getRequestScopes(), scopeStrategy)

        openIdConnectRequestValidator.validateRequest(request)

        val oidcSession = request.getSession().assertType<OidcSession>()

        if (request.getResponseTypes().contains(ResponseType.Token)) {
            oauthImplicitFlow.issueImplicitAccessToken(request, response)

            oidcSession.getIdTokenClaims().setAccessTokenHash(
                    openIdConnectTokenStrategy.leftMostHash(response.getFragments().singleValue("access_token")))
        } else {
            response.addFragment("state", request.getState())
        }

        response.addFragment("id_token", openIdConnectTokenStrategy.generateIdToken(request).token)
        request.setResponseTypeHandled(ResponseType.IdToken)
    }

    private fun AuthorizeRequest.shouldHandle(): Boolean {
        if (this.getResponseTypes().exactly(ResponseType.IdToken))
            return true

        if (this.getResponseTypes().containsAll(listOf(ResponseType.Token, ResponseType.IdToken)) &&
                this.getGrantedScopes().contains("openid"))
            return true

        if (!this.getResponseTypes().contains(ResponseType.Code))
            return true

        return false
    }
}