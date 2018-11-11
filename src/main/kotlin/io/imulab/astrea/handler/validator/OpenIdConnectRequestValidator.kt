package io.imulab.astrea.handler.validator

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.assertType
import io.imulab.astrea.error.RequestParameterInvalidValueException
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

            request.getIdTokenHint().run {
                if (isNotEmpty() &&
                        jwtRs256.decode(this, extraCriteria = { b ->
                            b.setSkipDefaultAudienceValidation()
                        }).jwtClaims.subject != it.session.getIdTokenClaims().subject)
                    throw RequestParameterInvalidValueException.MismatchedSubjectClaim(PARAM_ID_TOKEN_HINT)
            }
        }
    }

    companion object {
        private const val authTimeLeeway: Long = 5

        class ValidOidcRequest(val request: OAuthRequest) {

            val session = request.getSession().assertType<OidcSession>()

            val prompts: List<Prompt> = request.getPrompts()

            val authTime: NumericDate? = session.getIdTokenClaims().getAuthTime()

            val reqTime: NumericDate? = session.getIdTokenClaims().getRequestAtTime()

            val maxAge: Long? = request.getMaxAgeOrNull()

            fun mustOnlyAllowedPrompts(allowed: List<Prompt>) {
                if (!allowed.containsAll(prompts))
                    throw RequestParameterInvalidValueException(
                            PARAM_PROMPT,
                            prompts.joinToString(separator = SPACE) { it.specValue },
                            "Contains disallowed prompt value.")
            }

            fun mustStandaloneNonePrompt() {
                if (prompts.size > 1 && prompts.contains(Prompt.None))
                    throw RequestParameterInvalidValueException(PARAM_PROMPT, "'none' prompt requested along with others.")
            }

            fun mustNotNonePromptIfPublicClient() {
                if (request.getClient().isPublic() && prompts.contains(Prompt.None))
                    throw RequestParameterInvalidValueException(PARAM_PROMPT, "public client requiring user consent, but provided 'none' as prompt.")
            }

            fun mustNotEmptyClaimSubject() {
                if (session.getIdTokenClaims().subject.isEmpty())
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "claim subject is empty.")
            }

            fun optionalAuthTimeIsBeforeNow(leewaySeconds: Long = 0) {
                if (authTime != null && authTime.isOnOrAfter(NumericDate.now().plusSeconds(leewaySeconds)))
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "auth_time is before now.")
            }

            fun mustAuthTime() {
                if (authTime == null)
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "auth_time not specified.")
            }

            fun mustRequestTime() {
                if (reqTime == null)
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "rat not specified.")
            }

            fun mustAuthTimePlusMaxAgeIsAfterRequestTime() {
                if (authTime!!.plusSeconds(maxAge!!).isBefore(reqTime!!))
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "rat expired beyond auth_time and max_age")
            }

            fun mustAuthTimeIsBeforeRequestTime() {
                if (authTime!!.isAfter(reqTime!!))
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "auth_time happened after rat.")
            }

            fun mustAuthTimeIsAfterRequestTime() {
                if (authTime!!.isBefore(reqTime!!))
                    throw RequestParameterInvalidValueException(PARAM_ID_TOKEN, "auth_time happened after rat.")
            }
        }
    }
}