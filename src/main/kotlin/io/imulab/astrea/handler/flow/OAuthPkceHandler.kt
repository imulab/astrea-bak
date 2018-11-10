package io.imulab.astrea.handler.flow

import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.requireNotNullOrEmpty
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.handler.validator.PkceValidator
import io.imulab.astrea.spi.http.mustSingleValue
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.storage.PkceSessionStorage
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy

class OAuthPkceHandler(
        private val authorizeCodeStrategy: AuthorizeCodeStrategy,
        private val pkceSessionStorage: PkceSessionStorage,
        private val pkceValidator: PkceValidator,
        private val allowPlainChallengeMethod: Boolean = false
) : AuthorizeEndpointHandler, TokenEndpointHandler {

    override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
        if (!request.getResponseTypes().exactly(ResponseType.Code) || !request.getClient().isPublic())
            return

        require(response.getCode().isNotEmpty()) {
            "pkce handler must be placed behind authorize code handler, did upstream overlook this?"
        }

        request.getRequestForm().mustSingleValue(PARAM_CODE_CHALLENGE)
        request.getRequestForm().singleValue(PARAM_CODE_CHALLENGE_METHOD).let {
            return@let if (it.isBlank()) CodeChallengeMethod.Plain else CodeChallengeMethod.fromSpecValue(it)
        }.let {
            if (!allowPlainChallengeMethod && it == CodeChallengeMethod.Plain)
                throw RequestParameterInvalidValueException.UnsupportedCodeChallengeMethod(CodeChallengeMethod.Plain)
        }

        authorizeCodeStrategy.fromRaw(response.getCode()).run {
            pkceSessionStorage.createPkceSession(this, request.sanitize(listOf(
                    PARAM_CODE_CHALLENGE,
                    PARAM_CODE_CHALLENGE_METHOD
            )))
        }
    }

    override fun supports(request: AccessRequest): Boolean =
            request.getGrantTypes().exactly(GrantType.AuthorizationCode) && request.getClient().isPublic()

    override fun handleAccessRequest(request: AccessRequest) {
        if (!supports(request))
            return

        requireNotNull(request.getSession()) { "session must not be null" }

        val authorizeRequest = request.getRequestForm()
                .mustSingleValue(PARAM_CODE)
                .requireNotNullOrEmpty(PARAM_CODE)
                .let { authorizeCodeStrategy.fromRaw(it) }
                .let { c ->
                    pkceSessionStorage.getPkceSession(c).also {
                        pkceSessionStorage.deletePkceSession(c)
                    }
                }

        val codeVerifier = request.getRequestForm()
                .mustSingleValue(PARAM_CODE_VERIFIER)
                .requireNotNullOrEmpty(PARAM_CODE_VERIFIER)
        val codeChallenge = authorizeRequest.getRequestForm()
                .mustSingleValue(PARAM_CODE_CHALLENGE)
                .requireNotNullOrEmpty(PARAM_CODE_CHALLENGE) { IllegalStateException("Server lost previously saved $PARAM_CODE_CHALLENGE.") }
        val codeChallengeMethod = authorizeRequest.getRequestForm()
                .singleValue(PARAM_CODE_CHALLENGE_METHOD)
                .let { return@let if (it.isBlank()) CodeChallengeMethod.Plain else CodeChallengeMethod.fromSpecValue(it) }

        pkceValidator.validate(codeChallengeMethod, codeChallenge, codeVerifier)
    }

    override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {}
}