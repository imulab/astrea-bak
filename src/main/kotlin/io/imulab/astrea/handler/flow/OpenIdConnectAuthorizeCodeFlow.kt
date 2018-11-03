package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.error.ScopeNotGrantedException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.storage.OpenIdConnectRequestStorage
import io.imulab.astrea.token.strategy.IdTokenStrategy
import java.security.MessageDigest
import java.util.*

class OpenIdConnectAuthorizeCodeFlow(
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

    private val sha256: MessageDigest by lazy { MessageDigest.getInstance("SHA-256") }
    private val base64Encoder: Base64.Encoder by lazy { Base64.getUrlEncoder().withoutPadding() }

    // start: AuthorizeEndpointHandler ---------------------------------------------------------------------------------

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.shouldHandle())
            return

        if (response.getCode().isEmpty())
            throw IllegalStateException("program error: authorize code not issued.")

        openIdConnectRequestValidator.validateRequest(request)

        openIdConnectRequestStorage.createOidcSession(
                AuthorizeCode.fromRaw(response.getCode()),
                request.sanitize(openIdConnectSafeStorageParameters))
    }

    private fun AuthorizeRequest.shouldHandle(): Boolean {
        return this.getResponseTypes().size == 1 &&
                this.getResponseTypes().contains(ResponseType.Code) &&
                this.getGrantedScopes().contains("openid")
    }

    // end: AuthorizeEndpointHandler -----------------------------------------------------------------------------------

    // start: AuthorizeEndpointHandler ---------------------------------------------------------------------------------

    override fun handleAccessRequest(request: AccessRequest): Boolean = false

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.shouldHandle())
            return false

        val authorizeRequest = openIdConnectRequestStorage.getOidcSession(
                AuthorizeCode.fromRaw(request.getRequestForm().singleValue("code")),
                request
        )

        if (!authorizeRequest.getGrantedScopes().contains("openid"))
            throw ScopeNotGrantedException("openid")

        request.getClient().mustGrantType(GrantType.AuthorizationCode)

        val oidcSession = request.getSession() as? OidcSession
                ?: throw IllegalStateException("expected oidc session")

        if (oidcSession.getIdTokenClaims().subject.isEmpty())
            throw IllegalArgumentException("subject is empty.")

        oidcSession.getIdTokenClaims().setStringClaim("at_hash",
                sha256.digest(response.getAccessToken().toByteArray()).let {
                    base64Encoder.encodeToString(it.copyOfRange(0, it.size / 2))
                })

        response.setExtra("id_token", openIdTokenStrategy.generateIdToken(request).token)

        return true
    }

    private fun AccessRequest.shouldHandle(): Boolean {
        return this.getGrantTypes().size == 1 && this.getGrantTypes().contains(GrantType.AuthorizationCode)
    }

// end: AuthorizeEndpointHandler -----------------------------------------------------------------------------------
}