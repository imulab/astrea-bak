package io.imulab.astrea.handler.validator

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.Prompt
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.spi.http.singleValue
import org.jose4j.jwt.NumericDate

class OpenIdConnectRequestValidator(
        private val allowedPrompts: List<Prompt> = listOf(
                Prompt.Login,
                Prompt.None,
                Prompt.Consent,
                Prompt.SelectAccount
        ),
        private val jwtRs256: JwtRs256) {

    fun validateRequest(request: AuthorizeRequest) {
        ValidOidcRequest(request).also {
            // prompts
            it.mustOnlyAllowedPrompts(allowedPrompts)
            it.mustStandaloneNonePrompt()
            it.mustNotNonePromptIfPublicClient()
            when {
                it.prompts.contains(Prompt.None) -> {
                    it.mustAuthTime()
                    it.mustRequestTime()
                    it.mustAuthTimeIsBeforeRequestTime()
                }
                it.prompts.contains(Prompt.Login) -> {
                    if (it.authTime != null && it.reqTime != null)
                        it.mustAuthTimeIsAfterRequestTime()
                }
            }

            // claim
            it.mustNotEmptyClaimSubject()

            // auth_time
            it.optionalAuthTimeIsBeforeNow(authTimeLeeway)

            // max_age
            if (it.maxAge != null) {
                it.mustAuthTime()
                it.mustRequestTime()
                it.mustAuthTimePlusMaxAgeIsAfterRequestTime()
            }

            request.getRequestForm().singleValue("id_token_hint").also { hint ->
                if (hint.isNotEmpty()) {
                    if (jwtRs256.decode(hint).jwtClaims.subject != it.session.getIdTokenClaims().subject)
                        throw IllegalArgumentException("mismatched subject from id_token_hint")
                }
            }
        }
    }

    companion object {
        private const val authTimeLeeway: Long = 5

        class ValidOidcRequest(val request: OAuthRequest) {

            val session: OidcSession = request.getSession() as? OidcSession
                    ?: throw IllegalStateException("program error: session is not oidc session.")

            val prompts: List<Prompt> = request.getRequestForm()
                    .singleValue("prompt")
                    .split(" ")
                    .map{ Prompt.fromSpecValue(it) }
                    .toList()

            val authTime: NumericDate? = session.getIdTokenClaims()
                    .getNumericDateClaimValue("auth_time")

            val reqTime: NumericDate? = session.getIdTokenClaims()
                    .getNumericDateClaimValue("rat")

            val maxAge: Long? = request.getRequestForm()
                    .singleValue("max_age")
                    .toLongOrNull()

            fun mustOnlyAllowedPrompts(allowed: List<Prompt>) {
                if (!allowed.containsAll(prompts))
                    throw IllegalArgumentException("Contains disallowed prompt value.")
            }

            fun mustStandaloneNonePrompt() {
                if (prompts.size > 1 && prompts.contains(Prompt.None))
                    throw IllegalArgumentException("'none' prompt requested along with others.")
            }

            fun mustNotNonePromptIfPublicClient() {
                if (request.getClient().isPublic() && prompts.contains(Prompt.None))
                    throw IllegalArgumentException("public client requiring user consent, but provided 'none' as prompt.")
            }

            fun mustNotEmptyClaimSubject() {
                if (session.getIdTokenClaims().subject.isEmpty())
                    throw IllegalArgumentException("claim subject is empty.")
            }

            fun optionalAuthTimeIsBeforeNow(leewaySeconds: Long = 0) {
                if (authTime != null && authTime.isOnOrAfter(NumericDate.now().plusSeconds(leewaySeconds)))
                    throw IllegalArgumentException("auth_time is before now.")
            }

            fun mustAuthTime() {
                if (authTime == null)
                    throw IllegalArgumentException("auth_time not specified.")
            }

            fun mustRequestTime() {
                if (reqTime == null)
                    throw IllegalArgumentException("rat not specified.")
            }

            fun mustAuthTimePlusMaxAgeIsAfterRequestTime() {
                if (authTime!!.plusSeconds(maxAge!!).isBefore(reqTime!!))
                    throw IllegalArgumentException("rat expired beyond auth_time and max_age")
            }

            fun mustAuthTimeIsBeforeRequestTime() {
                if (authTime!!.isAfter(reqTime!!))
                    throw IllegalArgumentException("auth_time happened after rat.")
            }

            fun mustAuthTimeIsAfterRequestTime() {
                if (authTime!!.isBefore(reqTime!!))
                    throw IllegalArgumentException("auth_time happened after rat.")
            }

            private fun NumericDate.plusSeconds(seconds: Long): NumericDate =
                    NumericDate.fromSeconds(this.value + seconds)
        }
    }
}