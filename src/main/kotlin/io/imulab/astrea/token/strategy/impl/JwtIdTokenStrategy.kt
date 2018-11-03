package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.Prompt
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.IdToken
import io.imulab.astrea.token.strategy.IdTokenStrategy
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class JwtIdTokenStrategy(private val jwtRs256: JwtRs256,
                         private val issuer: String) : IdTokenStrategy {

    override fun generateIdToken(request: OAuthRequest): IdToken {
        val session = request.getSession()!! as? OidcSession
                ?: throw IllegalStateException("program error: session is not oidc session.")

        val expiry = request.getSession()!!.getExpiry(TokenType.IdToken)
                ?: throw IllegalStateException("program error: id token expiry not set.")

        if (session.getIdTokenClaims().subject.isBlank())
            throw IllegalArgumentException("id token subject is not set.")

        if (request.getGrantType() != GrantType.RefreshToken)
            whenGrantTypeIsNotRefreshToken(request)

        val jwt = jwtRs256.generate(session.getIdTokenClaims().also {
            it.setExpirationTimeMinutesInTheFuture(LocalDateTime.now().until(expiry, ChronoUnit.MINUTES).toFloat())

            it.setAuthTime(NumericDate.now())

            if (it.issuer.isEmpty())
                it.issuer = issuer

            if (request.getNonce().isNotEmpty())
                it.setNonce(request.getNonce())

            it.setAudience(*(
                    it.audience.also { aud -> aud.add(request.getClient().getId()) }.toSet().toTypedArray()
                    ))

            it.issuedAt = NumericDate.now()
        }, session.getIdTokenHeaders())

        return IdToken(
                token = jwt,
                signature = jwt.split(".")[2]
        )
    }

    private fun whenGrantTypeIsNotRefreshToken(request: OAuthRequest) {
        OpenIdConnectRequestValidator.Companion.ValidOidcRequest(request).also {
            it.optionalAuthTimeIsBeforeNow(authTimeLeeway)

            if (it.maxAge != null) {
                it.mustAuthTime()
                it.mustRequestTime()
                it.mustAuthTimePlusMaxAgeIsAfterRequestTime()
            }

            if (it.prompts.isNotEmpty()) {
                it.mustAuthTime()

                if (it.prompts.size > 1)
                    throw IllegalArgumentException("multiple prompts")
                when (it.prompts[0]) {
                    Prompt.None -> {
                        it.mustAuthTime()
                        it.mustRequestTime()
                        it.mustAuthTimeIsBeforeRequestTime()
                    }
                    Prompt.Login -> {
                        it.mustAuthTime()
                        it.mustRequestTime()
                        it.mustAuthTimeIsAfterRequestTime()
                    }
                }
            }

            if (it.request.getRequestForm().singleValue("acr_value").isNotEmpty() &&
                    it.session.getIdTokenClaims().getStringClaimValue("acr").isEmpty())
                it.session.getIdTokenClaims().setStringClaim("acr", "0")

            request.getRequestForm().singleValue("id_token_hint").also { hint ->
                if (hint.isNotEmpty()) {
                    if (jwtRs256.decode(hint).jwtClaims.subject != it.session.getIdTokenClaims().subject)
                        throw IllegalArgumentException("mismatched subject from id_token_hint")
                }
            }
        }
    }

    private fun OAuthRequest.getNonce(): String =
            this.getRequestForm().singleValue("nonce")

    private fun OAuthRequest.getGrantType(): GrantType =
            GrantType.fromSpecValue(this.getRequestForm().singleValue("grant_type"))

    private fun JwtClaims.setAuthTime(time: NumericDate) {
        this.setNumericDateClaim("auth_time", time)
    }

    private fun JwtClaims.setNonce(nonce: String) {
        this.setStringClaim("nonce", nonce)
    }

    private companion object {
        const val authTimeLeeway: Long = 5
    }
}