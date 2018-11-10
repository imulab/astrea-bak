package io.imulab.astrea.handler

import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.flow.OAuthImplicitHandler
import io.imulab.astrea.handler.flow.OpenIdConnectImplicitHandler
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

object OpenIdConnectImplicitHandlerSpec : Spek({

    val memoryStorage = MemoryStorage()

    val handler = OpenIdConnectImplicitHandler(
            oauthImplicitHandler = OAuthImplicitHandler(
                    scopeStrategy = StringEqualityScopeStrategy,
                    accessTokenStorage = memoryStorage,
                    accessTokenStrategy = TokenSupport.AccessToken.defaultStrategy
            ),
            openIdConnectTokenStrategy = TokenSupport.IdToken.defaultStraegy,
            scopeStrategy = StringEqualityScopeStrategy,
            openIdConnectRequestValidator = OpenIdConnectRequestValidator(
                    jwtRs256 = JwtRs256(jwk = KeySupport.defaultJwk),
                    allowedPrompts = listOf(Prompt.Login, Prompt.None))
    )

    describe("correct flow requesting token and id_token") {

        val flow = Flow()

        it("""
            should handle authorize request
        """.trimIndent()) {
            flow.makeAuthorizeRequest(
                    responseTypes = setOf(ResponseType.Token, ResponseType.IdToken),
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600)
            ) { authorizeRequest, authorizeResponse ->
                assertThatCode {
                    handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                }.doesNotThrowAnyException()
            }
        }

        it("""
            should have issued tokens
        """.trimIndent()) {
            assertThat(flow.response.getCode()).isEmpty()
            assertThat(flow.response.getAccessTokenFromFragment()).isNotEmpty()
            assertThat(flow.response.getIdTokenFromFragment()).isNotEmpty()
        }

        afterGroup { memoryStorage.clearAll() }
    }

    describe("correct flow requesting id_token only") {

        val flow = Flow()

        it("""
            should handle authorize request
        """.trimIndent()) {
            flow.makeAuthorizeRequest(
                    responseTypes = setOf(ResponseType.IdToken),
                    authTime = NumericDate.now().minusSeconds(300),
                    reqAtTime = NumericDate.now().minusSeconds(600)
            ) { authorizeRequest, authorizeResponse ->
                assertThatCode {
                    handler.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
                }.doesNotThrowAnyException()
            }
        }

        it("""
            should have issued tokens
        """.trimIndent()) {
            assertThat(flow.response.getCode()).isEmpty()
            assertThat(flow.response.getAccessTokenFromFragment()).isEmpty()
            assertThat(flow.response.getIdTokenFromFragment()).isNotEmpty()
        }

        afterGroup { memoryStorage.clearAll() }
    }

}) {

    private class Flow {

        var request: AuthorizeRequest? = null
        var response: AuthorizeResponse = DefaultAuthorizeResponse()

        fun makeAuthorizeRequest(responseTypes: Set<ResponseType>,
                                 requestSubject: String = "imulab",
                                 authTime: NumericDate,
                                 reqAtTime: NumericDate,
                                 prompt: Prompt = Prompt.Login,
                                 maxAge: Int = 600,
                                 nonce: String = "1234567890",
                                 callback: (AuthorizeRequest, AuthorizeResponse) -> Unit) {
            request = RequestSupport.newAuthorizeRequest(responseTypes = responseTypes,
                    scopes = setOf("foo", SCOPE_OPENID),
                    grantedScopes = setOf(SCOPE_OPENID),
                    client = ClientSupport.bar(),
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

            callback(request!!, response)
        }
    }
}