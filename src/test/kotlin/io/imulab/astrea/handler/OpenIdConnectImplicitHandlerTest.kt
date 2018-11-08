package io.imulab.astrea.handler

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.getAccessTokenFromFragment
import io.imulab.astrea.domain.extension.getIdTokenFromFragment
import io.imulab.astrea.domain.extension.setAuthTime
import io.imulab.astrea.domain.extension.setRequestAtTime
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.flow.OAuthImplicitHandler
import io.imulab.astrea.handler.flow.OpenIdConnectImplicitHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtIdTokenStrategy
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.function.Executable
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.function.BiConsumer

class OpenIdConnectImplicitHandlerTest {

    @ParameterizedTest(name = "#{index}: {0}")
    @MethodSource("handleAuthorizeRequestParams")
    fun testHandleAuthorizeRequest(
            @Suppress("UNUSED_PARAMETER") name: String,
            request: AuthorizeRequest,
            response: AuthorizeResponse,
            expectException: Class<Throwable>?,
            additionalAssert: BiConsumer<AuthorizeRequest, AuthorizeResponse>?
    ) {
        val executable = Executable {
            TestContext.handler.handleAuthorizeRequest(request, response)
        }

        if (expectException != null)
            Assertions.assertThrows(expectException, executable)
        else {
            Assertions.assertDoesNotThrow(executable)
        }

        additionalAssert?.accept(request, response)
    }

    @AfterEach
    fun cleanUp() {
        TestContext.memoryStorage.clearAll()
    }

    companion object {
        @JvmStatic
        fun handleAuthorizeRequestParams() = listOf(
                Arguments.of(
                        "response_type=token id_token",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Token, ResponseType.IdToken)
                                addScopes(SCOPE_OPENID, "foo")
                                addGrantedScopes(SCOPE_OPENID)

                                setClient(TestContext.defaultClient)

                                setSession(DefaultOidcSession.Builder().also {
                                    it.getClaims().run {
                                        subject = "imulab"
                                        // satisfies: rat < auth_time when prompt=login
                                        // automatically satisfies auth_time + max_age > rat
                                        setAuthTime(nowMinusSeconds(300))
                                        setRequestAtTime(nowMinusSeconds(600))
                                    }
                                }.build())

                                setForm(PARAM_NONCE, "1234567890")
                                setForm(PARAM_PROMPT, Prompt.Login.specValue)
                                setForm(PARAM_MAX_AGE, "600")
                                setForm(PARAM_ID_TOKEN_HINT, jwtWithClaims {
                                    subject = "imulab"
                                })

                                setState("12345678")
                            }
                        }.build(),
                        DefaultAuthorizeResponse(),
                        null,
                        BiConsumer<AuthorizeRequest, AuthorizeResponse> { _, resp ->
                            Assertions.assertDoesNotThrow {
                                Assertions.assertTrue(resp.getCode().isEmpty())
                                Assertions.assertTrue(resp.getAccessTokenFromFragment().isNotEmpty())
                                Assertions.assertTrue(resp.getIdTokenFromFragment().isNotEmpty())
                            }
                        }
                ),

                Arguments.of(
                        "response_type=id_token",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.IdToken)
                                addScopes(SCOPE_OPENID, "foo")
                                addGrantedScopes(SCOPE_OPENID)

                                setClient(TestContext.defaultClient)

                                setSession(DefaultOidcSession.Builder().also {
                                    it.getClaims().run {
                                        subject = "imulab"
                                        // satisfies: rat < auth_time when prompt=login
                                        // automatically satisfies auth_time + max_age > rat
                                        setAuthTime(nowMinusSeconds(300))
                                        setRequestAtTime(nowMinusSeconds(600))
                                    }
                                }.build())

                                setForm(PARAM_NONCE, "1234567890")
                                setForm(PARAM_PROMPT, Prompt.Login.specValue)
                                setForm(PARAM_MAX_AGE, "600")
                                setForm(PARAM_ID_TOKEN_HINT, jwtWithClaims {
                                    subject = "imulab"
                                })

                                setState("12345678")
                            }
                        }.build(),
                        DefaultAuthorizeResponse(),
                        null,
                        BiConsumer<AuthorizeRequest, AuthorizeResponse> { _, resp ->
                            Assertions.assertDoesNotThrow {
                                Assertions.assertTrue(resp.getCode().isEmpty())
                                Assertions.assertTrue(resp.getAccessTokenFromFragment().isEmpty())
                                Assertions.assertTrue(resp.getIdTokenFromFragment().isNotEmpty())
                            }
                        }
                )
        )

        private fun nowMinusSeconds(seconds: Long): NumericDate =
                NumericDate.fromSeconds(NumericDate.now().value - seconds)

        private fun jwtWithClaims(f: JwtClaims.() -> Unit): String =
                JsonWebSignature().also {
                    it.payload = JwtClaims().also { c -> c.setGeneratedJwtId(); c.f() }.toJson()
                    it.key = TestContext.jwk.rsaPrivateKey
                    it.keyIdHeaderValue = TestContext.jwk.keyId
                    it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
                }.compactSerialization
    }

    private object TestContext {
        val jwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.use = Use.SIGNATURE
                it.keyId = "test"
            }
        }

        val defaultClient = DefaultOidcClient(
                oauth = DefaultOAuthClient(
                        id = "foo",
                        secret = "s3cret".toByteArray(),
                        responseTypes = listOf(ResponseType.Code, ResponseType.IdToken),
                        grantTypes = listOf(GrantType.AuthorizationCode, GrantType.Implicit),
                        scopes = listOf(SCOPE_OPENID, "email", "profile", "foo"),
                        redirectUris = listOf("https://test.com/callback"),
                        public = false
                ),
                jwk = JsonWebKeySet().also { it.addJsonWebKey(jwk) },
                tokenEndpointAuth = AuthMethod.PrivateKeyJwt,
                reqObjSignAlg = SigningAlgorithm.RS256
        )

        val jwtRs256 = JwtRs256(jwk = jwk)

        val memoryStorage by lazy { MemoryStorage() }

        val openIdConnectRequestValidator = OpenIdConnectRequestValidator(
                jwtRs256 = jwtRs256,
                allowedPrompts = listOf(Prompt.Login, Prompt.None))

        val openIdTokenStrategy = JwtIdTokenStrategy(jwtRs256 = jwtRs256, issuer = "foo")

        val accessTokenStrategy = JwtAccessTokenStrategy(jwtRs256 = jwtRs256, issuer = "foo")

        val handler = OpenIdConnectImplicitHandler(
                oauthImplicitHandler = OAuthImplicitHandler(
                        scopeStrategy = StringEqualityScopeStrategy,
                        accessTokenStorage = memoryStorage,
                        accessTokenStrategy = accessTokenStrategy
                ),
                openIdConnectTokenStrategy = openIdTokenStrategy,
                scopeStrategy = StringEqualityScopeStrategy,
                openIdConnectRequestValidator = openIdConnectRequestValidator
        )
    }
}