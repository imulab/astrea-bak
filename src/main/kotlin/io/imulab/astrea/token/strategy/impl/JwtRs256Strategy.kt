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
) : AccessTokenStrategy, IdTokenStrategy {

    // start: IdTokenStrategy ------------------------------------------------------------------------------------------

    override fun generateIdToken(request: OAuthRequest): IdToken {
        // TODO: move bits irrelevant with JWT out of here.
        val expiry = request.getSession()!!.getExpiry(TokenType.IdToken)
                ?: throw IllegalStateException("program error: id token expiry not set.")

        val session = request.getSession()!! as? OidcSession
                ?: throw IllegalStateException("program error: session is not oidc session.")
        if (session.getIdTokenClaims().subject.isBlank())
            throw IllegalArgumentException("id token subject is not set.")

        // TODO assuming nonce is already checked
        val nonce = request.getRequestForm().singleValue("nonce")

        if (request.getRequestForm().singleValue("grant_type") != GrantType.RefreshToken.specValue) {
            val authTime = session.getIdTokenClaims().getAuthTime()
            if (authTime?.isOnOrAfter(NumericDate.now().also { it.addSeconds(5) }) == true)
                throw IllegalArgumentException("auth_time is before now.")

            val requestTime = session.getIdTokenClaims().getRequestAtTime()

            val maxAge = request.getRequestForm().singleValue("max_age").toLongOrNull() ?: 0L
            if (maxAge > 0) {
                if (authTime == null)
                    throw IllegalArgumentException("no auth_time in claims when max_age is set.")

                if (requestTime == null)
                    throw IllegalArgumentException("no rat in claims when max_age is set.")

                if (NumericDate.fromSeconds(authTime.value + maxAge).isBefore(requestTime))
                    throw IllegalArgumentException("rat expired beyond auth_time and max_age")
            }

            val prompt = request.getRequestForm().singleValue("prompt")
            if (prompt.isNotEmpty()) {
                if (authTime == null)
                    throw IllegalArgumentException("unable to verify prompt, auth_time is not set.")
                else {
                    when (prompt) {
                        "none" -> {
                            if (authTime.isAfter(requestTime))
                                throw IllegalArgumentException("auth time after request time. user has logged in during request.")
                        }
                        "login" -> {
                            if (authTime.isBefore(requestTime))
                                throw IllegalArgumentException("auth time before request time. user has not re-authenticated.")
                        }
                    }
                }
            }

            if (request.getRequestForm().singleValue("acr_value").isNotEmpty() &&
                    session.getIdTokenClaims().getAuthenticationContextClassReference().isEmpty())
                session.getIdTokenClaims().setAuthenticationContextClassReference("0")

            val tokenHintRaw = request.getRequestForm().singleValue("id_token_hint")
            if (tokenHintRaw.isNotEmpty()) {
                try {
                    JwtConsumerBuilder()
                            .setJwsAlgorithmConstraints(SigningAlgorithm.RS256.toJwsAlgorithmConstraints())
                            .setVerificationKey(this.jwk.getRsaPublicKey())
                            .setSkipDefaultAudienceValidation()
                            .setRequireIssuedAt()
                            .setRequireExpirationTime()
                            .build()
                            .processToClaims(tokenHintRaw).also {
                                if (it.subject != session.getIdTokenClaims().subject)
                                    throw IllegalArgumentException("mismatched subject from id_token_hint")
                            }
                } catch (e: InvalidJwtException) {
                    // TODO test for expired exception and allow it
                    throw e
                }
            }
        }

        session.getIdTokenClaims().let {
            it.setExpirationTimeMinutesInTheFuture(LocalDateTime.now().until(expiry, ChronoUnit.MINUTES).toFloat())
            if (it.expirationTime.isBefore(NumericDate.now()))
                throw java.lang.IllegalArgumentException("expiry cannot be set in the past.")

            it.setNumericDateClaim("auth_time", NumericDate.now())

            if (it.issuer.isEmpty())
                it.issuer = issuer

            if (nonce.isNotEmpty())
                it.setStringClaim("nonce", nonce)

            it.setAudience(*(
                    it.audience.also { aud -> aud.add(request.getClient().getId()) }.toSet().toTypedArray()
                    ))

            it.issuedAt = NumericDate.now()
        }

        val jwt = generateJwt(session.getIdTokenClaims(), session.getIdTokenHeaders())
        return IdToken(
                token = jwt,
                signature = doComputeSignature(jwt)
        )
    }

    // end: IdTokenStrategy --------------------------------------------------------------------------------------------

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