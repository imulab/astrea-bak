package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.JwtSession
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.error.InvalidAccessTokenException
import io.imulab.astrea.error.TokenInvalidity
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.IdToken
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.IdTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import java.lang.Exception
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class JwtRs256Strategy(private val issuer: String,
                       private val jwk: RsaJsonWebKey
) : AccessTokenStrategy {

    private fun generateJwt(claims: JwtClaims, headers: Map<String, String>): String {
        return JsonWebSignature().also {
            headers.forEach(it::setHeader)
            it.payload = claims.toJson()
            it.key = jwk.rsaPrivateKey
            it.keyIdHeaderValue = jwk.keyId
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
        }.compactSerialization
    }

    // start: AccessTokenStrategy --------------------------------------------------------------------------------------

    override fun computeAccessTokenSignature(token: String): String =
            doComputeSignature(token)

    override fun generateNewAccessToken(request: OAuthRequest): AccessToken {
        if (request.getSession() !is JwtSession)
            throw IllegalStateException("session is not jwt typed.")

        val session = request.getSession() as JwtSession
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
            it.setStringListClaim("scope", request.getGrantedScopes())
        }

        val jwt = generateJwt(session.getJwtClaims(), session.getJwtHeaders())
        return AccessToken(
                token = jwt,
                signature = doComputeSignature(jwt)
        )
    }

    override fun validateAccessToken(request: OAuthRequest, token: String) {
        JwtConsumerBuilder()
                .setRequireJwtId()
                .setJwsAlgorithmConstraints(SigningAlgorithm.RS256.toJwsAlgorithmConstraints())
                .setVerificationKey(this.jwk.getRsaPublicKey())
                .setExpectedIssuer(true, issuer)
                .setSkipDefaultAudienceValidation()
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .build()
                .process(token)
    }

    private fun doComputeSignature(token: String): String {
        val parts = token.split(".")
        if (parts.size != 3)
            throw InvalidAccessTokenException(TokenInvalidity.BadFormat, accessTokenFormatInstruction)
        return parts[2]
    }

    // end: AccessTokenStrategy ----------------------------------------------------------------------------------------

    companion object {
        const val accessTokenFormatInstruction = "Proper access token should have three parts, delimited by \".(dot)\"."
    }
}