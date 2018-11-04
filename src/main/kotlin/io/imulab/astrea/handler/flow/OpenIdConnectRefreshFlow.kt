package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.exactly
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.domain.extension.setAccessTokenHash
import io.imulab.astrea.domain.extension.setIdToken
import io.imulab.astrea.domain.extension.setNonce
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

        val oidcSession = request.getSession().assertType<OidcSession>().also {
            if (it.getIdTokenClaims().subject.isEmpty())
                throw IllegalArgumentException("subject is empty.")
        }

        response.getAccessToken()
                .let { openIdConnectTokenStrategy.leftMostHash(it) }
                .let { oidcSession.getIdTokenClaims().setAccessTokenHash(it) }

        openIdConnectTokenStrategy.generateIdToken(request).let {
            response.setIdToken(it.token)
        }

        return true
    }

    private fun AccessRequest.shouldHandle(): Boolean {
        return this.getGrantTypes().exactly(GrantType.RefreshToken) &&
                this.getGrantedScopes().contains("openid") &&
                this.getClient().mustGrantType(GrantType.RefreshToken, false)
    }
}