package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.JwtSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.error.InvalidAccessTokenException
import io.imulab.astrea.error.TokenInvalidity
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class JwtAccessTokenStrategy(private val jwtRs256: JwtRs256,
                             private val issuer: String) : AccessTokenStrategy {

    override fun fromRaw(raw: String): AccessToken {
        val parts = requireThreeParts(raw)
        return AccessToken(
                token = raw,
                signature = parts[2]
        )
    }

    override fun computeAccessTokenSignature(token: String): String {
        return requireThreeParts(token)[2]
    }

    override fun generateNewAccessToken(request: OAuthRequest): AccessToken {
        val session = request.getSession().assertType<JwtSession>()

        if (session.getJwtClaims().claimsMap.isEmpty())
            throw IllegalArgumentException("claim must not be empty.")

        val expiry = session.getExpiry(TokenType.AccessToken)
                ?: throw IllegalArgumentException("expiry must be set")

        session.getJwtClaims().also {
            it.setGeneratedJwtId()
            it.issuer = issuer
            it.audience = listOf(request.getClient().getId())
            it.setIssuedAtToNow()
            it.setExpirationTimeMinutesInTheFuture(LocalDateTime.now().until(expiry, ChronoUnit.MINUTES).toFloat())
            it.setScopes(request.getGrantedScopes())
        }

        val jwt = jwtRs256.generate(session.getJwtClaims(), session.getJwtHeaders())

        return AccessToken(
                token = jwt,
                signature = computeAccessTokenSignature(jwt)
        )
    }

    override fun validateAccessToken(request: OAuthRequest, token: String) {
        val t = jwtRs256.validate(token) {
            it.setRequireJwtId()
            it.setExpectedIssuer(true, issuer)
            it.setSkipDefaultAudienceValidation()
            it.setRequireIssuedAt()
            it.setRequireExpirationTime()
        }
        if (t != null)
            throw InvalidAccessTokenException(TokenInvalidity.BadSignature, t.message)  // TODO update to correct cause
    }

    private fun requireThreeParts(raw: String): List<String> {
        val parts = raw.split(".")
        if (parts.size != 3)
            throw InvalidAccessTokenException(TokenInvalidity.BadFormat)
        return parts
    }
}