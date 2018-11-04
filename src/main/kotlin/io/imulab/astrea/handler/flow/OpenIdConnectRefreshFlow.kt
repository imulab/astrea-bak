package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.exactly
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.domain.setAccessTokenHash
import io.imulab.astrea.domain.setNonce
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.token.strategy.IdTokenStrategy

class OpenIdConnectRefreshFlow(
        private val openIdConnectTokenStrategy: IdTokenStrategy
) : TokenEndpointHandler {

    override fun handleAccessRequest(request: AccessRequest): Boolean {
        if (!request.shouldHandle())
            return false

        request.getSession().assertType<OidcSession>().also {
            // reset
            it.getIdTokenClaims().expirationTime = null
            it.getIdTokenClaims().setNonce("")
        }

        return true
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
        if (!request.shouldHandle())
            return false

        request.getSession().assertType<OidcSession>().also {
            if (it.getIdTokenClaims().subject.isEmpty())
                throw IllegalArgumentException("subject is empty.")

            it.getIdTokenClaims().setAccessTokenHash(openIdConnectTokenStrategy.leftMostHash(response.getAccessToken()))
        }

        response.setExtra("id_token", openIdConnectTokenStrategy.generateIdToken(request).token)

        return true
    }

    private fun AccessRequest.shouldHandle(): Boolean {
        return this.getGrantTypes().exactly(GrantType.RefreshToken) &&
                this.getGrantedScopes().contains("openid") &&
                this.getClient().mustGrantType(GrantType.RefreshToken, false)
    }
}