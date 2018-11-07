package io.imulab.astrea.handler.impl

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.extension.getScopes
import io.imulab.astrea.domain.extension.toLocalDateTime
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.response.impl.DefaultIntrospectResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.handler.IntrospectEndpointHandler

/**
 * A stateless implementation of [IntrospectEndpointHandler] which validates and decodes the presented JWT access token
 * and reconstructs an [AccessRequest] as close as possible (some information, like grant type, was not encoded in jwt,
 * hence inevitably lost).
 */
class AccessTokenJwtIntrospectHandler(private val jwtRs256: JwtRs256,
                                      private val issuer: String) : IntrospectEndpointHandler {

    override fun inspects(): Collection<TokenType> = listOf(TokenType.AccessToken)

    override fun introspectToken(request: IntrospectRequest): IntrospectResponse {
        return try {
            val ctx = jwtRs256.decode(request.getToken()) {
                it.setRequireJwtId()
                it.setExpectedIssuer(true, issuer)
                it.setSkipDefaultAudienceValidation()
                it.setRequireIssuedAt()
                it.setRequireExpirationTime()
            }
            DefaultIntrospectResponse(
                    active = true,
                    tokenType = TokenType.AccessToken,
                    accessRequest = DefaultAccessRequest.Builder().also {
                        it.client = DefaultOAuthClient(id = ctx.jwtClaims.audience[0], secret = ByteArray(0))
                        it.reqTime = ctx.jwtClaims.issuedAt.toLocalDateTime()
                        ctx.jwtClaims.getScopes().forEach { granted ->
                            it.addGrantedScopes(granted)
                            it.addScopes(granted)
                        }
                        it.session = DefaultJwtSession(claims = ctx.jwtClaims, subject = ctx.jwtClaims.subject).also { s ->
                            s.setExpiry(TokenType.AccessToken, ctx.jwtClaims.expirationTime.toLocalDateTime())
                        }
                    }.build() as AccessRequest
            )
        } catch (_: Exception) {
            DefaultIntrospectResponse(active = false)
        }
    }
}