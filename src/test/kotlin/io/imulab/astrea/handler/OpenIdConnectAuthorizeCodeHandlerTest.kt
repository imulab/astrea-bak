package io.imulab.astrea.handler

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.crypt.SigningAlgorithm
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.extension.*
import io.imulab.astrea.domain.request.*
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.OidcSession
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.handler.impl.OpenIdConnectAuthorizeCodeHandler
import io.imulab.astrea.handler.validator.OpenIdConnectRequestValidator
import io.imulab.astrea.token.AuthorizeCode
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
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
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.Mockito
import java.util.function.BiConsumer
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class OpenIdConnectAuthorizeCodeHandlerTest {

    @ParameterizedTest(name = "#{index}: {0}")
    @MethodSource("authorizeRequestParams")
    fun testHandleAuthorizeRequest(
            @Suppress("UNUSED_PARAMETER") name: String,
            request: AuthorizeRequest,
            response: AuthorizeResponse,
            expectException: Class<Throwable>?,
            additionalAssert: BiConsumer<AuthorizeRequest, AuthorizeResponse>?) {
        val executable = Executable {
            TestContext.handler.handleAuthorizeRequest(request, response)
        }

        if (expectException != null)
            assertThrows(expectException, executable)
        else {
            assertDoesNotThrow(executable)
        }

        additionalAssert?.accept(request, response)
    }

    @Test
    fun testSupport() {
        val r1 = Mockito.mock(AccessRequest::class.java)
        Mockito.`when`(r1.getGrantTypes()).thenReturn(listOf(GrantType.AuthorizationCode))

        val r2 = Mockito.mock(AccessRequest::class.java)
        Mockito.`when`(r2.getGrantTypes()).thenReturn(listOf(GrantType.AuthorizationCode, GrantType.Password))

        assertTrue(TestContext.handler.supports(r1))
        assertFalse(TestContext.handler.supports(r2))
    }

    @Test
    fun testPopulateAccessRequest() {
        // got lazy: just borrow test parameters from #testHandleAuthorizeRequest
        // the second parameter of the first test is the one that represents a correct request.
        val authCode = newAuthorizeCode()
        (authorizeRequestParams()[0].get()[1] as OAuthRequest).run {
            TestContext.memoryStorage.createOidcSession(AuthorizeCode(code = authCode, signature = "unimportant"), this)
        }

        val request = DefaultAccessRequest.Builder().also {
            it.setForm(PARAM_CODE, authCode)
            it.setForm(PARAM_GRANT_TYPE, GrantType.AuthorizationCode.specValue) // because id token strategy looks up in form.
            it.addGrantType(GrantType.AuthorizationCode)

            it.client = TestContext.defaultClient
            it.session = DefaultOidcSession.Builder().also { s ->
                s.getClaims().run { subject = "imulab" }
            }.build()
        }.build() as AccessRequest

        val response = DefaultAccessResponse().also {
            it.setAccessToken(jwtWithClaims { subject = "for-test-only" })
        }

        TestContext.handler.populateAccessResponse(request, response)

        assertTrue((request.getSession()!! as OidcSession).getIdTokenClaims().getAccessTokenHash().isNotEmpty())
        assertTrue(response.getIdToken().isNotEmpty())
    }

    @AfterEach
    fun cleanUp() {
        TestContext.memoryStorage.clearAll()
    }

    companion object {
        @JvmStatic
        fun authorizeRequestParams() = listOf(
                // testHandleAuthorizeRequest#1
                Arguments.of(
                        "valid request should pass",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code)
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
                        BiConsumer<AuthorizeRequest, AuthorizeResponse> { _, resp ->
                            assertDoesNotThrow {
                                TestContext.memoryStorage.getOidcSession(
                                        AuthorizeCode(code = resp.getCode(), signature = "not.important"),
                                        Mockito.mock(OAuthRequest::class.java)
                                )
                            }
                        }
                ),

                // testHandleAuthorizeRequest#2
                Arguments.of(
                        "disallowed prompts should be rejected",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code)
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

                                setForm(PARAM_PROMPT, Prompt.Consent.specValue)

                                setState("12345678")
                            }
                        }.build(),
                        DefaultAuthorizeResponse().also {
                            it.setCodeAsQuery(newAuthorizeCode())
                        },
                        IllegalArgumentException::class.java,
                        null
                ),

                // testHandleAuthorizeRequest#3
                Arguments.of(
                        "auth_time after rat when prompt=none should be rejected",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code)
                                addGrantedScopes(SCOPE_OPENID)

                                setClient(TestContext.defaultClient)

                                setSession(DefaultOidcSession.Builder().also {
                                    it.getClaims().run {
                                        subject = "imulab"
                                        setAuthTime(nowMinusSeconds(300))
                                        setRequestAtTime(nowMinusSeconds(600))
                                    }
                                }.build())

                                setForm(PARAM_PROMPT, Prompt.None.specValue)
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
                        IllegalArgumentException::class.java,
                        null
                ),

                // testHandleAuthorizeRequest#4
                Arguments.of(
                        "max_age expired should be rejected",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code)
                                addGrantedScopes(SCOPE_OPENID)

                                setClient(TestContext.defaultClient)

                                setSession(DefaultOidcSession.Builder().also {
                                    it.getClaims().run {
                                        subject = "imulab"
                                        setAuthTime(nowMinusSeconds(600))
                                        setRequestAtTime(nowMinusSeconds(300))
                                    }
                                }.build())

                                setForm(PARAM_PROMPT, Prompt.None.specValue)
                                setForm(PARAM_MAX_AGE, "200")
                                setForm(PARAM_ID_TOKEN_HINT, jwtWithClaims {
                                    subject = "imulab"
                                })

                                setState("12345678")
                            }
                        }.build(),
                        DefaultAuthorizeResponse().also {
                            it.setCodeAsQuery(newAuthorizeCode())
                        },
                        IllegalArgumentException::class.java,
                        null
                ),

                // testHandleAuthorizeRequest#5
                Arguments.of(
                        "mismatched claim subject should be rejected",
                        DefaultAuthorizeRequest.Builder().also { b ->
                            b.run {
                                addResponseTypes(ResponseType.Code)
                                addGrantedScopes(SCOPE_OPENID)

                                setClient(TestContext.defaultClient)

                                setSession(DefaultOidcSession.Builder().also {
                                    it.getClaims().run {
                                        subject = "this-is-a-mismatch"
                                        setAuthTime(nowMinusSeconds(300))
                                        setRequestAtTime(nowMinusSeconds(600))
                                    }
                                }.build())

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
                        IllegalArgumentException::class.java,
                        null
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
                        grantTypes = listOf(GrantType.AuthorizationCode),
                        scopes = listOf(SCOPE_OPENID, "email", "profile", "foo"),
                        redirectUris = listOf("https://test.com/callback"),
                        public = false
                ),
                jwk = JsonWebKeySet().also { it.addJsonWebKey(TestContext.jwk) },
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

        val handler: OpenIdConnectAuthorizeCodeHandler = OpenIdConnectAuthorizeCodeHandler(
                authorizeCodeStrategy = authorizeCodeStrategy,
                openIdConnectRequestStorage = memoryStorage,
                openIdConnectRequestValidator = openIdConnectRequestValidator,
                openIdTokenStrategy = openIdTokenStrategy
        )
    }
}