package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.exactly
import io.imulab.astrea.domain.extension.setAccessTokenHash
import io.imulab.astrea.domain.extension.setIdToken
import io.imulab.astrea.domain.extension.setNonce
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.token.strategy.IdTokenStrategy

class OpenIdConnectRefreshFlow(
        private val openIdConnectTokenStrategy: IdTokenStrategy
) : TokenEndpointHandler {

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.RefreshToken) &&
                    request.getGrantedScopes().contains("openid") &&
                    request.getClient().mustGrantType(GrantType.RefreshToken, false)

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        request.getSession().assertType<OidcSession>().also {
            // reset
            it.getIdTokenClaims().expirationTime = null
            it.getIdTokenClaims().setNonce("")
        }
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

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
    }
}