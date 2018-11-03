package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.error.ScopeRejectedException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.strategy.IdTokenStrategy
import java.security.MessageDigest
import java.util.*

class OpenIdConnectImplicitFlow(
        private val oauthImplicitFlow: OAuthImplicitFlow,
        private val scopeStrategy: ScopeStrategy,
        private val openIdConnectTokenStrategy: IdTokenStrategy,
        private val openIdConnectRequestValidator: OpenIdConnectRequestValidator,
        private val minimumNonceEntropy: Int = 8
) : AuthorizeEndpointHandler {

    private val sha256: MessageDigest by lazy { MessageDigest.getInstance("SHA-256") }
    private val base64Encoder: Base64.Encoder by lazy { Base64.getUrlEncoder().withoutPadding() }

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

        request.getRequestScopes().find { requested ->
            request.getClient().getScopes().none { registered -> scopeStrategy.accepts(registered, requested) }
        }.let {
            if (it != null)
                throw ScopeRejectedException(it)
        }

        openIdConnectRequestValidator.validateRequest(request)

        val oidcSession = request.getSession().assertType<OidcSession>()

        if (request.getResponseTypes().contains(ResponseType.Token)) {
            oauthImplicitFlow.issueImplicitAccessToken(request, response)

            oidcSession.getIdTokenClaims().setStringClaim("at_hash",
                    sha256.digest(response.getFragments().singleValue("access_token").toByteArray()).let {
                        base64Encoder.encodeToString(it.copyOfRange(0, it.size / 2))
                    })
        } else {
            response.addFragment("state", request.getState())
        }

        response.addFragment("id_token", openIdConnectTokenStrategy.generateIdToken(request).token)
        request.setResponseTypeHandled(ResponseType.IdToken)
    }

    private fun AuthorizeRequest.shouldHandle(): Boolean {
        if (this.getResponseTypes().size == 1 && this.getResponseTypes().contains(ResponseType.IdToken))
            return true

        if (this.getResponseTypes().containsAll(listOf(ResponseType.Token, ResponseType.IdToken)) &&
                this.getGrantedScopes().contains("openid"))
            return true

        if (!this.getResponseTypes().contains(ResponseType.Code))
            return true

        return false
    }
}