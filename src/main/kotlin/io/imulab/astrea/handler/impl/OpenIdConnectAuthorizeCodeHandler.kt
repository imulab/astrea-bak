package io.imulab.astrea.handler.impl

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getCode
import io.imulab.astrea.domain.extension.setAccessTokenHash
import io.imulab.astrea.domain.extension.setIdToken
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

class OpenIdConnectAuthorizeCodeHandler(
        private val authorizeCodeStrategy: AuthorizeCodeStrategy,
        private val openIdConnectRequestStorage: OpenIdConnectRequestStorage,
        private val openIdConnectRequestValidator: OpenIdConnectRequestValidator,
        private val openIdTokenStrategy: IdTokenStrategy,
        private val openIdConnectSafeStorageParameters: List<String> = listOf(
                PARAM_GRANT_TYPE,
                PARAM_MAX_AGE,
                PARAM_PROMPT,
                PARAM_ACR_VALUE,
                PARAM_ID_TOKEN_HINT,
                PARAM_NONCE
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
        return this.getResponseTypes().exactly(ResponseType.Code) && this.getGrantedScopes().contains(SCOPE_OPENID)
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

        if (!authorizeRequest.getGrantedScopes().contains(SCOPE_OPENID))
            throw ScopeNotGrantedException(SCOPE_OPENID)

        request.getClient().mustGrantType(GrantType.AuthorizationCode)

        request.getSession().assertType<OidcSession>().run {
            if (getIdTokenClaims().subject.isEmpty())
                throw IllegalArgumentException("subject is empty.")

            response.getAccessToken()
                    .let { openIdTokenStrategy.leftMostHash(it) }
                    .let { getIdTokenClaims().setAccessTokenHash(it) }
        }

        response.setIdToken(openIdTokenStrategy.generateIdToken(request).token)
    }

    // end: TokenEndpointHandler ---------------------------------------------------------------------------------------
}