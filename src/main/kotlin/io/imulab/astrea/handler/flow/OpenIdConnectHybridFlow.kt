package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.error.ScopeRejectedException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.storage.AuthorizeCodeStorage
import io.imulab.astrea.token.storage.OpenIdConnectRequestStorage
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.IdTokenStrategy
import java.security.MessageDigest
import java.util.*

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
                "grant_type",
                "max_age",
                "prompt",
                "acr_values",
                "id_token_hint",
                "nonce"
        )
) : AuthorizeEndpointHandler, TokenEndpointHandler by openIdConnectAuthorizeCodeFlow {

    private val sha256: MessageDigest by lazy { MessageDigest.getInstance("SHA-256") }
    private val base64Encoder: Base64.Encoder by lazy { Base64.getUrlEncoder().withoutPadding() }

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.shouldHandle())
            return

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

        val oidcSession = request.getSession() as? OidcSession
                ?: throw IllegalStateException("program error: expect oidc session.")

        if (request.getResponseTypes().contains(ResponseType.Code)) {
            request.getClient().mustGrantType(GrantType.AuthorizationCode)

            val authorizeCode = authorizeCodeStrategy.generateNewAuthorizeCode(request).also {
                authorizeCodeStorage.createAuthorizeCodeSession(it, request.sanitize(authorizeCodeSafeStorageParameters))
            }

            response.addFragment("code", authorizeCode.code)
            request.setResponseTypeHandled(ResponseType.Code)

            oidcSession.getIdTokenClaims().setStringClaim("c_hash",
                    sha256.digest(response.getCode().toByteArray()).let {
                        base64Encoder.encodeToString(it.copyOfRange(0, it.size / 2))
                    })

            if (request.getGrantedScopes().contains("openid"))
                openIdConnectRequestStorage.createOidcSession(authorizeCode, request.sanitize(openIdConnectSafeStorageParameters))
        }

        if (request.getResponseTypes().contains(ResponseType.Token)) {
            request.getClient().mustGrantType(GrantType.Implicit)

            oAuthImplicitFlow.issueImplicitAccessToken(request, response)
            request.setResponseTypeHandled(ResponseType.Token)

            oidcSession.getIdTokenClaims().setStringClaim("at_hash",
                    sha256.digest(response.getFragments().singleValue("access_token").toByteArray()).let {
                        base64Encoder.encodeToString(it.copyOfRange(0, it.size / 2))
                    })
        }

        if (response.getFragments().singleValue("state").isEmpty())
            response.addFragment("state", request.getState())

        if (request.getGrantedScopes().contains("openid") &&
                request.getResponseTypes().contains(ResponseType.IdToken))
            response.addFragment("id_token", openIdConnectTokenStrategy.generateIdToken(request).token)

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