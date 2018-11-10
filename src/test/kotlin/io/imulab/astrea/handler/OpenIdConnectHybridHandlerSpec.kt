package io.imulab.astrea.handler

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.flow.OAuthImplicitHandler
import io.imulab.astrea.handler.flow.OpenIdConnectAuthorizeCodeHandler
import io.imulab.astrea.handler.flow.OpenIdConnectHybridHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.support.ClientSupport
import io.imulab.astrea.support.KeySupport
import io.imulab.astrea.support.RequestSupport
import io.imulab.astrea.support.TokenSupport
import io.imulab.astrea.token.storage.impl.MemoryStorage
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.jose4j.jwt.NumericDate
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OpenIdConnectHybridHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()

    val validator = OpenIdConnectRequestValidator(
            jwtRs256 = JwtRs256(jwk = KeySupport.defaultJwk),
            allowedPrompts = listOf(Prompt.Login, Prompt.None))

    val handler = OpenIdConnectHybridHandler(
            openIdConnectAuthorizeCodeHandler = OpenIdConnectAuthorizeCodeHandler(
                    authorizeCodeStrategy = TokenSupport.AuthorizeCode.defaultStrategy,
                    openIdConnectRequestValidator = validator,
                    openIdTokenStrategy = TokenSupport.IdToken.defaultStraegy,
                    openIdConnectRequestStorage = memoryStorage
            ),
            openIdConnectRequestStorage = memoryStorage,
            openIdConnectRequestValidator = validator,
            authorizeCodeStrategy = TokenSupport.AuthorizeCode.defaultStrategy,
            scopeStrategy = StringEqualityScopeStrategy,
            authorizeCodeStorage = memoryStorage,
            openIdConnectTokenStrategy = TokenSupport.IdToken.defaultStraegy,
            oAuthImplicitHandler = OAuthImplicitHandler(
                    accessTokenStorage = memoryStorage,
                    accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy,
                    scopeStrategy = StringEqualityScopeStrategy
            )
    )

    describe("correct flow requesting code and token") {

        val flow = Flow()

        it("""
            should handle authorize request
        """.trimIndent()) {
                flow.makeAuthorizeRequest(
                        authTime = NumericDate.now().minusSeconds(300),
                        reqAtTime = NumericDate.now().minusSeconds(600),
                        responseTypes = setOf(ResponseType.Code, ResponseType.Token)
                ) { authorizeRequest, authorizeResponse ->
                    assertThatCode {
                        handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                    }.doesNotThrowAnyException()
                }
        }

        it("""
            should have issued access token and code, but not id_token
        """.trimIndent()) {
            assertThat(flow.authorizeRequest)
                    .isNotNull
                    .extracting { it!!.getSession() }
                    .isInstanceOf(OidcSession::class.java)
                    .extracting { (it as OidcSession).getIdTokenClaims().getAccessTokenHash() }
                    .asString()
                    .isNotBlank()
            flow.authorizeResponse.run {
                assertThat(getAccessTokenFromFragment()).isNotEmpty()
                assertThat(getCode()).isNotEmpty()
                assertThat(getIdTokenFromFragment()).isEmpty()
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("correct flow requesting code and id_token") {

        val flow = Flow()

        it("""
            should handle authorize request
        """.trimIndent()) {
            flow.makeAuthorizeRequest(
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600),
                    responseTypes = setOf(ResponseType.Code, ResponseType.IdToken)
            ) { authorizeRequest, authorizeResponse ->
                assertThatCode {
                    handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                }.doesNotThrowAnyException()
            }
        }

        it("""
            should have issued code and id_token, but not access_token
        """.trimIndent()) {
            assertThat(flow.authorizeRequest)
                    .isNotNull
                    .extracting { it!!.getSession() }
                    .isInstanceOf(OidcSession::class.java)
                    .extracting { (it as OidcSession).getIdTokenClaims().getAccessTokenHash() }
                    .asString()
                    .isEmpty()
            flow.authorizeResponse.run {
                assertThat(getCode()).isNotEmpty()
                assertThat(getIdTokenFromFragment()).isNotEmpty()
                assertThat(getAccessTokenFromFragment()).isEmpty()
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

    describe("correct flow requesting code, token and id_token") {

        val flow = Flow()

        it("""
            should handle authorize request
        """.trimIndent()) {
            flow.makeAuthorizeRequest(
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600),
                    responseTypes = setOf(ResponseType.Code, ResponseType.Token, ResponseType.IdToken)
            ) { authorizeRequest, authorizeResponse ->
                assertThatCode {
                    handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                }.doesNotThrowAnyException()
            }
        }

        it("""
            should have issued access token and code, and id_token
        """.trimIndent()) {
            assertThat(flow.authorizeRequest)
                    .isNotNull
                    .extracting { it!!.getSession() }
                    .isInstanceOf(OidcSession::class.java)
                    .extracting { (it as OidcSession).getIdTokenClaims().getAccessTokenHash() }
                    .asString()
                    .isNotBlank()
            flow.authorizeResponse.run {
                assertThat(getAccessTokenFromFragment()).isNotEmpty()
                assertThat(getCode()).isNotEmpty()
                assertThat(getIdTokenFromFragment()).isNotEmpty()
            }
        }

        afterGroup {
            memoryStorage.clearAll()
        }
    }

}) {

    private class Flow {

        val code = TokenSupport.AuthorizeCode.new()
        var authorizeRequest: AuthorizeRequest? = null
        var authorizeResponse: AuthorizeResponse = DefaultAuthorizeResponse().also {
            it.setCodeAsQuery(code.code)
        }

        fun makeAuthorizeRequest(requestSubject: String = "imulab",
                                 authTime: NumericDate,
                                 reqAtTime: NumericDate,
                                 prompt: Prompt = Prompt.Login,
                                 maxAge: Int = 600,
                                 nonce: String = "1234567890",
                                 responseTypes: Set<ResponseType>,
                                 callback: (AuthorizeRequest, AuthorizeResponse) -> Unit) {
            authorizeRequest = RequestSupport.newAuthorizeRequest(
                    client = ClientSupport.bar(),
                    responseTypes = responseTypes,
                    scopes = setOf("foo", SCOPE_OPENID),
                    grantedScopes = setOf(SCOPE_OPENID),
                    session = DefaultOidcSession.Builder().also {
                        it.getClaims().run {
                            subject = requestSubject
                            setAuthTime(authTime)
                            setRequestAtTime(reqAtTime)
                        }
                    }.build(),
                    form = mapOf(
                            PARAM_NONCE to listOf(nonce),
                            PARAM_PROMPT to listOf(prompt.specValue),
                            PARAM_MAX_AGE to listOf(maxAge.toString()),
                            PARAM_ID_TOKEN_HINT to listOf(TokenSupport.customJwt(subject = requestSubject))
                    )
            )

            callback(authorizeRequest!!, authorizeResponse)
        }
    }
}