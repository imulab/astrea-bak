package io.imulab.astrea.token.strategy.impl

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.crypt.hash.Hasher
import io.imulab.astrea.crypt.hash.ShaHasher
import io.imulab.astrea.domain.DOT
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.Prompt
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.IdToken
import io.imulab.astrea.token.strategy.IdTokenStrategy
import org.jose4j.jwt.NumericDate
import java.time.Duration
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalAmount

class JwtIdTokenStrategy(private val jwtRs256: JwtRs256,
                         private val issuer: String,
                         private val idTokenLifespan: TemporalAmount = Duration.ofHours(1)) : IdTokenStrategy {

    override fun getHasher(): Hasher = ShaHasher.usingSha256()

    override fun generateIdToken(request: OAuthRequest): IdToken {
        val session = request.getSession().assertType<OidcSession>()

        require(session.getIdTokenClaims().subject.isNotEmpty()) {
            "oidc session id token subject claim is not set, did upstream overlook this?"
        }

        if (!request.getGrantTypes().contains(GrantType.RefreshToken))
            whenGrantTypeIsNotRefreshToken(request)

        val jwt = jwtRs256.generate(session.getIdTokenClaims().also {
            // we can only get ChronoUnit.SECONDS here since Duration only supports SECONDS and NANO
            it.setExpirationTimeMinutesInTheFuture(idTokenLifespan.get(ChronoUnit.SECONDS).div(60).toFloat())

            it.setAuthTime(NumericDate.now())

            if (it.issuer.isNullOrEmpty())
                it.issuer = issuer

            if (request.getNonce().isNotEmpty())
                it.setNonce(request.getNonce())

            it.setAudience(*(it.audience.toHashSet().also { s -> s.add(request.getClient().getId()) }.toTypedArray()))

            it.issuedAt = NumericDate.now()
        }, session.getIdTokenHeaders())

        return IdToken(
                token = jwt,
                signature = jwt.split(DOT)[2]
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
                    else -> {
                    }
                }
            }

            it.request.getAuthenticationContextClassReferenceValue().run {
                if (isNotEmpty() && it.session.getIdTokenClaims().getAuthenticationContextClassReference().isEmpty())
                    it.session.getIdTokenClaims().setAuthenticationContextClassReference("0")
            }

            request.getIdTokenHint().run {
                if (isNotEmpty() &&
                        jwtRs256.decode(this).jwtClaims.subject != it.session.getIdTokenClaims().subject)
                    throw RequestParameterInvalidValueException.MismatchedSubjectClaim(source = "id_token_hint")
            }
        }
    }

    private companion object {
        const val authTimeLeeway: Long = 5
    }
}