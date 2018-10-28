package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.error.InvalidAccessTokenException
import io.imulab.astrea.domain.JwtSession
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.SigningAlgorithm
import io.imulab.astrea.domain.TokenType
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class JwtRs256Strategy(private val issuer: String,
                       private val jwk: RsaJsonWebKey) : AccessTokenStrategy {

    override fun computeAccessTokenSignature(token: String): String =
            doComputeSignature(token)

    override fun generateNewAccessToken(request: OAuthRequest): AccessToken =
            doGenerate(TokenType.AccessToken, request)

    override fun validateAccessToken(request: OAuthRequest, token: String) {
        doValidate(token)
    }

    private fun doGenerate(tokenType: TokenType, request: OAuthRequest): AccessToken {
        if (request.getSession() !is JwtSession)
            throw IllegalStateException("session is not jwt typed.")

        val session = request.getSession() as JwtSession
        if (session.getJwtClaims().claimsMap.isEmpty())
            throw IllegalArgumentException("claim must not be empty.")

        val expiry = session.getExpiry(tokenType) ?: throw IllegalArgumentException("expiry must be set")

        session.getJwtClaims().also {
            it.setGeneratedJwtId()
            it.issuer = issuer
            it.audience = listOf(request.getClient().getId())
            it.setIssuedAtToNow()
            it.setExpirationTimeMinutesInTheFuture(LocalDateTime.now().until(expiry, ChronoUnit.MINUTES).toFloat())
            it.setStringListClaim("scope", request.getGrantedScopes())
        }

        val jwt = JsonWebSignature().also {
            session.getJwtHeaders().forEach(it::setHeader)
            it.payload = session.getJwtClaims().toJson()
            it.key = jwk.rsaPrivateKey
            it.keyIdHeaderValue = jwk.keyId
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
        }.compactSerialization

        return AccessToken(
                token = jwt,
                signature = doComputeSignature(jwt)
        )
    }

    private fun doValidate(token: String): JwtContext =
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

    private fun doComputeSignature(token: String): String {
        val parts = token.split(".")
        if (parts.size != 3)
            throw InvalidAccessTokenException("malformed jwt.")
        return parts[2]
    }
}