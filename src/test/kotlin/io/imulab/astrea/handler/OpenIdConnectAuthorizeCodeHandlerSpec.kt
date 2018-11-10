package io.imulab.astrea.handler

import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.handler.flow.OpenIdConnectAuthorizeCodeHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.KeySupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.*
import org.jose4j.jwt.NumericDate
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OpenIdConnectAuthorizeCodeHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()
    val handler = OpenIdConnectAuthorizeCodeHandler(
            authorizeCodeStrategy = TokenSupport.AuthorizeCode.defaultStrategy,
            openIdConnectRequestValidator = OpenIdConnectRequestValidator(
                    jwtRs256 = JwtRs256(jwk = KeySupport.defaultJwk),
                    allowedPrompts = listOf(Prompt.Login, Prompt.None)),
            openIdTokenStrategy = TokenSupport.IdToken.defaultStraegy,
            openIdConnectRequestStorage = memoryStorage
    )

    describe("correct flow") {

        val flow = Flow()

        it("""should handle authorize request""") {
            flow.makeAuthorizeRequest(
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600)
            ) { authorizeRequest, authorizeResponse ->
                assertThatCode {
                    handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                }.doesNotThrowAnyException()
            }
        }

        it("""should handle access request""") {
            flow.makeAccessRequest { accessRequest ->
                assertThatCode {
                    handler.handleAccessRequest(accessRequest)
                }.doesNotThrowAnyException()
            }
        }

        it("""should populate access request""") {
            assertThat(flow.accessRequest).isNotNull
            assertThatCode {
                handler.populateAccessResponse(flow.accessRequest!!, flow.accessResponse)
            }.doesNotThrowAnyException()
        }

        it("""should have issued id token""") {
            assertThat(flow.accessRequest)
                    .isNotNull
                    .extracting { it!!.getSession() }
                    .isNotNull()
                    .isInstanceOf(OidcSession::class.java)
                    .extracting { (it as OidcSession).getIdTokenClaims().getAccessTokenHash() }
                    .asString()
                    .isNotBlank()
            assertThat(flow.accessResponse)
                    .extracting { it.getIdToken() }
                    .asString()
                    .isNotBlank()
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("failure modes") {

        it("""
            disallowed prompts should be rejected
        """.trimIndent()) {
            val flow = Flow()

            // this is not supported at the moment, but might change in the future
            flow.makeAuthorizeRequest(prompt = Prompt.SelectAccount,
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600)) { authorizeRequest, authorizeResponse ->
                assertThatExceptionOfType(RequestParameterInvalidValueException::class.java)
                        .isThrownBy { handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse) }
            }
        }

        it("""
            auth_time after rat when prompt=none should be rejected
        """.trimIndent()) {
            val flow = Flow()

            // this is not supported at the moment, but might change in the future
            flow.makeAuthorizeRequest(prompt = Prompt.None,
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600)) { authorizeRequest, authorizeResponse ->
                assertThatExceptionOfType(RequestParameterInvalidValueException::class.java)
                        .isThrownBy { handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse) }
            }
        }

        it("""
            max_age expired should be rejected
        """.trimIndent()) {
            val flow = Flow()
            flow.makeAuthorizeRequest(prompt = Prompt.Login,
                    authTime = NumericDate.now().minusSeconds(600),
                    reqAtTime = NumericDate.now().minusSeconds(300),
                    maxAge = 200) { authorizeRequest, authorizeResponse ->
                assertThatExceptionOfType(RequestParameterInvalidValueException::class.java)
                        .isThrownBy { handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse) }
            }
        }

        it("""
            mismatched claim subject should be rejected
        """.trimIndent()) {
            val flow = Flow()
            flow.makeAuthorizeRequest(
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600)
            ) { authorizeRequest, authorizeResponse ->
                assertThatExceptionOfType(RequestParameterInvalidValueException.MismatchedSubjectClaim::class.java)
                        .isThrownBy {
                            handler.handleAuthorizeRequest(authorizeRequest.also {
                                (it.getSession() as OidcSession).getIdTokenClaims().subject = "mismatch"
                            }, authorizeResponse)
                        }
            }
        }

        afterEachTest {
            memoryStorage.clearAll()
        }
    }

}) {

    private class Flow {

        val code = TokenSupport.AuthorizeCode.new()

        var accessRequest: AccessRequest? = null
        var accessResponse: AccessResponse = DefaultAccessResponse()

        fun makeAuthorizeRequest(requestSubject: String = "imulab",
                                 authTime: NumericDate,
                                 reqAtTime: NumericDate,
                                 prompt: Prompt = Prompt.Login,
                                 maxAge: Int = 600,
                                 callback: (AuthorizeRequest, AuthorizeResponse) -> Unit) {

            val authorizeRequest: AuthorizeRequest = RequestSupport.newAuthorizeRequest(
                    client = ClientSupport.bar(),
                    responseTypes = setOf(ResponseType.Code),
                    grantedScopes = setOf(SCOPE_OPENID),
                    session = DefaultOidcSession.Builder().also { b ->
                        b.getClaims().run {
                            subject = requestSubject
                            setAuthTime(authTime)
                            setRequestAtTime(reqAtTime)
                        }
                    }.build(),
                    form = mapOf(
                            PARAM_PROMPT to listOf(prompt.specValue),
                            PARAM_MAX_AGE to listOf(maxAge.toString()),
                            PARAM_ID_TOKEN_HINT to listOf(TokenSupport.customJwt(subject = requestSubject))
                    )
            )
            val authorizeResponse = DefaultAuthorizeResponse().also {
                it.setCodeAsQuery(code.code)
            }

            callback(authorizeRequest, authorizeResponse)
        }

        fun makeAccessRequest(requestSubject: String = "imulab",
                              grantType: GrantType = GrantType.AuthorizationCode,
                              code: String = this.code.code,
                              client: OAuthClient = ClientSupport.bar(),
                              callback: (AccessRequest) -> Unit) {
            accessRequest = RequestSupport.newAccessRequest(
                    grantTypes = setOf(grantType),
                    form = mapOf(
                            PARAM_CODE to listOf(code),
                            PARAM_GRANT_TYPE to listOf(grantType.specValue)
                    ),
                    client = client,
                    session = DefaultOidcSession.Builder().also { s ->
                        s.getClaims().run { subject = requestSubject }
                    }.build()
            )
            callback(accessRequest!!)
        }
    }
}