package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.exactly
import io.imulab.astrea.domain.extension.getCode
import io.imulab.astrea.domain.extension.setAccessTokenHash
import io.imulab.astrea.domain.extension.setRefreshToken
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.error.ScopeNotGrantedException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.storage.OpenIdConnectRequestStorage
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.IdTokenStrategy

class OpenIdConnectAuthorizeCodeFlow(
        private val authorizeCodeStrategy: AuthorizeCodeStrategy,
        private val openIdConnectRequestStorage: OpenIdConnectRequestStorage,
        private val openIdConnectRequestValidator: OpenIdConnectRequestValidator,
        private val openIdTokenStrategy: IdTokenStrategy,
        private val openIdConnectSafeStorageParameters: List<String> = listOf(
                "grant_type",
                "max_age",
                "prompt",
                "acr_values",
                "id_token_hint",
                "nonce"
        )
) : AuthorizeEndpointHandler, TokenEndpointHandler {

    // start: AuthorizeEndpointHandler ---------------------------------------------------------------------------------

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.shouldHandle())
            return

        if (response.getCode().isEmpty())
            throw IllegalStateException("program error: authorize code not issued.")

        openIdConnectRequestValidator.validateRequest(request)

        openIdConnectRequestStorage.createOidcSession(
                authorizeCodeStrategy.fromRaw(response.getCode()),
                request.sanitize(openIdConnectSafeStorageParameters))
    }

    private fun AuthorizeRequest.shouldHandle(): Boolean {
        return this.getResponseTypes().exactly(ResponseType.Code) && this.getGrantedScopes().contains("openid")
    }

    // end: AuthorizeEndpointHandler -----------------------------------------------------------------------------------

    // start: TokenEndpointHandler -------------------------------------------------------------------------------------

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.AuthorizationCode)

    override fun handleAccessRequest(request: AccessRequest) {}

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

        val authorizeRequest = openIdConnectRequestStorage.getOidcSession(
                authorizeCodeStrategy.fromRaw(request.getCode()),
                request)

        if (!authorizeRequest.getGrantedScopes().contains("openid"))
            throw ScopeNotGrantedException("openid")

        request.getClient().mustGrantType(GrantType.AuthorizationCode)

        request.getSession().assertType<OidcSession>().also { oidcSession ->
            if (oidcSession.getIdTokenClaims().subject.isEmpty())
                throw IllegalArgumentException("subject is empty.")

            response.getAccessToken()
                    .let { openIdTokenStrategy.leftMostHash(it) }
                    .let { oidcSession.getIdTokenClaims().setAccessTokenHash(it) }
        }

        response.setRefreshToken(openIdTokenStrategy.generateIdToken(request).token)
    }

    // end: TokenEndpointHandler ---------------------------------------------------------------------------------------
}