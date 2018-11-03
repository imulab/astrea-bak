package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.token.strategy.IdTokenStrategy
import java.security.MessageDigest
import java.util.*

class OpenIdConnectRefreshFlow(
        private val openIdConnectTokenStrategy: IdTokenStrategy
) : TokenEndpointHandler {

    private val sha256: MessageDigest by lazy { MessageDigest.getInstance("SHA-256") }
    private val base64Encoder: Base64.Encoder by lazy { Base64.getUrlEncoder().withoutPadding() }

    override fun handleAccessRequest(request: AccessRequest): Boolean {
        if (!request.shouldHandle())
            return false

        val oidcSession = request.getSession() as? OidcSession
                ?: throw IllegalStateException("program error: expect oidc session.")

        // reset
        oidcSession.getIdTokenClaims().expirationTime = null
        oidcSession.getIdTokenClaims().setStringClaim("nonce", "")

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.shouldHandle())
            return false

        val oidcSession = request.getSession() as? OidcSession
                ?: throw IllegalStateException("program error: expect oidc session.")

        if (oidcSession.getIdTokenClaims().subject.isEmpty())
            throw IllegalArgumentException("subject is empty.")

        oidcSession.getIdTokenClaims().setStringClaim("at_hash",
                sha256.digest(response.getAccessToken().toByteArray()).let {
                    base64Encoder.encodeToString(it.copyOfRange(0, it.size / 2))
                })

        response.setExtra("id_token", openIdConnectTokenStrategy.generateIdToken(request).token)

        return true
    }

    private fun AccessRequest.shouldHandle(): Boolean {
        return this.getGrantTypes().size == 1 &&
                this.getGrantTypes().contains(GrantType.RefreshToken) &&
                this.getGrantedScopes().contains("openid") &&
                this.getClient().mustGrantType(GrantType.RefreshToken, false)
    }
}