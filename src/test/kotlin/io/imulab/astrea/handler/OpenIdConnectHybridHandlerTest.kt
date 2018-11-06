package io.imulab.astrea.handler

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.impl.OAuthImplicitHandler
import io.imulab.astrea.handler.impl.OpenIdConnectAuthorizeCodeHandler
import io.imulab.astrea.handler.impl.OpenIdConnectHybridHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
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
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.function.Executable
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.Mockito
import java.util.function.BiConsumer
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class OpenIdConnectHybridHandlerTest {

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

    companion object {
        @JvmStatic
        fun handleAuthorizeRequestParams() = listOf(
                Arguments.of(
                        "response_type=code token",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code, ResponseType.Token)
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
                        DefaultAuthorizeResponse().also {
                            it.setCodeAsQuery(newAuthorizeCode())
                        },
                        null,
                        BiConsumer<AuthorizeRequest, AuthorizeResponse> { req, resp ->
                            Assertions.assertDoesNotThrow {
                                TestContext.memoryStorage.getOidcSession(
                                        AuthorizeCode(code = resp.getCode(), signature = "not.important"),
                                        Mockito.mock(OAuthRequest::class.java)
                                )
                                Assertions.assertTrue((req.getSession() as OidcSession).getIdTokenClaims().getAccessTokenHash().isNotEmpty())
                                Assertions.assertTrue(resp.getAccessTokenFromFragment().isNotEmpty())
                                Assertions.assertTrue(resp.getCode().isNotEmpty())
                                Assertions.assertTrue(resp.getIdTokenFromFragment().isEmpty())
                            }
                        }
                ),
                Arguments.of(
                        "response_type=code id_token",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code, ResponseType.IdToken)
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
                        DefaultAuthorizeResponse().also {
                            it.setCodeAsQuery(newAuthorizeCode())
                        },
                        null,
                        BiConsumer<AuthorizeRequest, AuthorizeResponse> { req, resp ->
                            Assertions.assertDoesNotThrow {
                                TestContext.memoryStorage.getOidcSession(
                                        AuthorizeCode(code = resp.getCode(), signature = "not.important"),
                                        Mockito.mock(OAuthRequest::class.java)
                                )
                                Assertions.assertTrue((req.getSession() as OidcSession).getIdTokenClaims().getAccessTokenHash().isEmpty())
                                Assertions.assertTrue(resp.getAccessTokenFromFragment().isEmpty())
                                Assertions.assertTrue(resp.getCode().isNotEmpty())
                                Assertions.assertTrue(resp.getIdTokenFromFragment().isNotEmpty())
                            }
                        }
                ),
                Arguments.of(
                        "response_type=code token id_token",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code, ResponseType.Token, ResponseType.IdToken)
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
                        DefaultAuthorizeResponse().also {
                            it.setCodeAsQuery(newAuthorizeCode())
                        },
                        null,
                        BiConsumer<AuthorizeRequest, AuthorizeResponse> { req, resp ->
                            Assertions.assertDoesNotThrow {
                                TestContext.memoryStorage.getOidcSession(
                                        AuthorizeCode(code = resp.getCode(), signature = "not.important"),
                                        Mockito.mock(OAuthRequest::class.java)
                                )
                                Assertions.assertTrue((req.getSession() as OidcSession).getIdTokenClaims().getAccessTokenHash().isNotEmpty())
                                Assertions.assertTrue((req.getSession() as OidcSession).getIdTokenClaims().getCodeHash().isNotEmpty())
                                Assertions.assertTrue(resp.getAccessTokenFromFragment().isNotEmpty())
                                Assertions.assertTrue(resp.getCode().isNotEmpty())
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

        private fun newAuthorizeCode(): String =
                TestContext.authorizeCodeStrategy.generateNewAuthorizeCode(Mockito.mock(OAuthRequest::class.java)).code
    }

    private object TestContext {
        val secretKey: SecretKey by lazy { KeyGenerator.getInstance("AES").generateKey() }

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

        val hmacSha256 = HmacSha256(secretKey = secretKey)

        val jwtRs256 = JwtRs256(jwk = jwk)

        val authorizeCodeStrategy = HmacAuthorizeCodeStrategy(hmac = hmacSha256)

        val memoryStorage by lazy { MemoryStorage() }

        val openIdConnectRequestValidator = OpenIdConnectRequestValidator(
                jwtRs256 = jwtRs256,
                allowedPrompts = listOf(Prompt.Login, Prompt.None))

        val openIdTokenStrategy = JwtIdTokenStrategy(jwtRs256 = jwtRs256, issuer = "foo")

        val accessTokenStrategy = JwtAccessTokenStrategy(jwtRs256 = jwtRs256, issuer = "foo")

        val handler = OpenIdConnectHybridHandler(
                authorizeCodeStrategy = authorizeCodeStrategy,
                openIdConnectRequestStorage = memoryStorage,
                openIdConnectRequestValidator = openIdConnectRequestValidator,
                scopeStrategy = StringEqualityScopeStrategy,
                authorizeCodeStorage = memoryStorage,
                openIdConnectTokenStrategy = openIdTokenStrategy,
                openIdConnectAuthorizeCodeHandler = OpenIdConnectAuthorizeCodeHandler(
                        authorizeCodeStrategy = authorizeCodeStrategy,
                        openIdConnectRequestStorage = memoryStorage,
                        openIdConnectRequestValidator = openIdConnectRequestValidator,
                        openIdTokenStrategy = openIdTokenStrategy
                ),
                oAuthImplicitHandler = OAuthImplicitHandler(
                        scopeStrategy = StringEqualityScopeStrategy,
                        accessTokenStorage = memoryStorage,
                        accessTokenStrategy = accessTokenStrategy
                )
        )
    }
}