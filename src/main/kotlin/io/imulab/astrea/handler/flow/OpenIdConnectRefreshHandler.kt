package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.SCOPE_OPENID
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

class OpenIdConnectRefreshHandler(
        private val openIdConnectTokenStrategy: IdTokenStrategy
) : TokenEndpointHandler {

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.RefreshToken) &&
                    request.getGrantedScopes().contains(SCOPE_OPENID) &&
                    request.getClient().mustGrantType(GrantType.RefreshToken, false)

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null" }

        request.getSession().assertType<OidcSession>().also {
            // reset
            it.getIdTokenClaims().expirationTime = null
            it.getIdTokenClaims().setNonce("")
        }
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null" }

        val oidcSession = request.getSession().assertType<OidcSession>().also {
            require(it.getIdTokenClaims().subject.isNotEmpty()) {
                "oidc session id token subject claim must not be empty. did upstream overlook this?"
            }
        }

        response.getAccessToken()
                .let { openIdConnectTokenStrategy.leftMostHash(it) }
                .let { oidcSession.getIdTokenClaims().setAccessTokenHash(it) }

        openIdConnectTokenStrategy.generateIdToken(request).run {
            response.setIdToken(token)
        }
    }
}