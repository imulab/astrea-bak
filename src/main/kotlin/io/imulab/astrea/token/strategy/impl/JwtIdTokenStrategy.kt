package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.Prompt
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.IdToken
import io.imulab.astrea.token.strategy.IdTokenStrategy
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

class JwtIdTokenStrategy(private val jwtRs256: JwtRs256,
                         private val issuer: String): IdTokenStrategy {

    override fun generateIdToken(request: OAuthRequest): IdToken {
        val session = request.getSession()!! as? OidcSession
                ?: throw IllegalStateException("program error: session is not oidc session.")

        val expiry = request.getSession()!!.getExpiry(TokenType.IdToken)
                ?: throw IllegalStateException("program error: id token expiry not set.")

        if (session.getIdTokenClaims().subject.isBlank())
            throw IllegalArgumentException("id token subject is not set.")

        if (request.getGrantType() != GrantType.RefreshToken)
            whenGrantTypeIsNotRefreshToken(session, request)

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

    private fun whenGrantTypeIsNotRefreshToken(session: OidcSession, request: OAuthRequest) {
        val authTime = session.getIdTokenClaims().getAuthTime()
        val requestTime = session.getIdTokenClaims().getRequestAtTime()

        if (authTime?.isOnOrAfter(NumericDate.now().plusSeconds(authTimeLeeway)) == true)
            throw IllegalArgumentException("auth_time is before now.")

        // check optional max_age. when provided, relation 'auth_time + max_age >= req_time' must hold.
        request.getMaxAge(0).also {
            if (it > 0) {
                when {
                    authTime == null ->
                        throw IllegalArgumentException("no auth_time in claims when max_age is set.")
                    requestTime == null ->
                        throw IllegalArgumentException("no rat in claims when max_age is set.")
                    authTime.plusSeconds(it).isBefore(requestTime) ->
                        throw IllegalArgumentException("rat expired beyond auth_time and max_age")
                }
            }
        }

        // check optional prompt.
        // when 'none', ensure user has not re-authenticated.
        // when 'login', ensure user has re-authenticated.
        request.getPrompt().also {
            if (it != null) {
                if (authTime == null)
                    throw IllegalArgumentException("unable to verify prompt, auth_time is not set.")

                when (it) {
                    Prompt.None -> {
                        if (authTime.isAfter(requestTime))
                            throw IllegalArgumentException("auth time after request time. user has logged in during request.")
                    }
                    Prompt.Login -> {
                        if (authTime.isBefore(requestTime))
                            throw IllegalArgumentException("auth time before request time. user has not re-authenticated.")
                    }
                }
            }
        }

        // fallback to level 0 (least confidence) if request provided acr but id_token did not
        if (request.getAcr().isNotEmpty() && session.getIdTokenClaims().getAcr().isEmpty())
            session.getIdTokenClaims().setAcr("0")

        // check hint subject == claim subject
        request.getIdTokenHint().also {hint ->
            if (hint.isNotEmpty()) {
                if (jwtRs256.decode(hint).jwtClaims.subject != session.getIdTokenClaims().subject)
                    throw IllegalArgumentException("mismatched subject from id_token_hint")
            }
        }
    }

    private fun OAuthRequest.getNonce(): String =
            this.getRequestForm().singleValue("nonce")

    private fun OAuthRequest.getGrantType(): GrantType =
            GrantType.fromSpecValue(this.getRequestForm().singleValue("grant_type"))

    private fun OAuthRequest.getPrompt(): Prompt? {
        val p = this.getRequestForm().singleValue("prompt")
        return if (p.isNotEmpty()) Prompt.fromSpecValue(p) else null
    }

    private fun OAuthRequest.getMaxAge(default: Long): Long =
            this.getRequestForm().singleValue("max_age").toLongOrNull() ?: default

    private fun OAuthRequest.getAcr(): String =
            this.getRequestForm().singleValue("acr_value")

    private fun OAuthRequest.getIdTokenHint(): String =
            this.getRequestForm().singleValue("id_token_hint")

    private fun JwtClaims.getAuthTime(): NumericDate?
            = this.getNumericDateClaimValue("auth_time")

    private fun JwtClaims.setAuthTime(time: NumericDate) {
        this.setNumericDateClaim("auth_time", time)
    }

    private fun JwtClaims.getRequestAtTime(): NumericDate?
            = this.getNumericDateClaimValue("rat")

    private fun JwtClaims.getAcr(): String =
            this.getStringClaimValue("acr") ?: ""

    private fun JwtClaims.setAcr(value: String) {
        this.setStringClaim("acr", value)
    }

    private fun JwtClaims.setNonce(nonce: String) {
        this.setStringClaim("nonce", nonce)
    }

    private fun NumericDate.plusSeconds(seconds: Long): NumericDate =
            NumericDate.fromSeconds(this.value + seconds)

    private companion object {
        const val authTimeLeeway: Long = 5
    }
}