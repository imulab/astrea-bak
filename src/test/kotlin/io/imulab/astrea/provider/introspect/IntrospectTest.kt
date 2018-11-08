package io.imulab.astrea.provider.introspect

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.client.auth.ClientBearerPreIntrospectionAuthenticator
import io.imulab.astrea.client.auth.ClientSecretBasicAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.PARAM_TOKEN_TYPE_HINT
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.TokenTypeHint
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.handler.IntrospectEndpointHandler
import io.imulab.astrea.handler.impl.AccessTokenJwtIntrospectHandler
import io.imulab.astrea.handler.impl.RefreshTokenStorageIntrospectHandler
import io.imulab.astrea.provider.IntrospectionProvider
import io.imulab.astrea.provider.impl.DefaultIntrospectionProvider
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.json.JsonEncoder
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.HmacRefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.function.Executable
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class IntrospectTest {

    @ParameterizedTest(name = "#{index}: {0}")
    @MethodSource("params")
    fun testProvider(
            @Suppress("UNUSED_PARAMETER") testName: String,
            params: TestParam
    ) {
        val accessTokens = params.accessTokenGen()
        val refreshTokens = params.refreshTokenGen()

        // http request
        val request = mock(HttpRequestReader::class.java)
                .also {
                    params.httpStub(it, accessTokens)
                }
                .also {
                    `when`(it.getForm()).thenReturn(params.httpBodyParams.also { m ->
                        if (accessTokens.isNotEmpty())
                            m[PARAM_TOKEN] = listOf(accessTokens[0].token)
                        else if (refreshTokens.isNotEmpty())
                            m[PARAM_TOKEN] = listOf(refreshTokens[0].token)
                    })
                }

        var introspectRequest: IntrospectRequest? = null
        val stageOne = Executable {
            introspectRequest = TestContext.provider.newIntrospectRequest(request, DefaultJwtSession(claims = JwtClaims()))
        }
        if (params.stageOneThrows != null) {
            assertThrows(params.stageOneThrows, stageOne)
            return
        } else {
            assertDoesNotThrow(stageOne)
        }

        assertNotNull(introspectRequest)

        var introspectResponse: IntrospectResponse? = null
        val stageTwo = Executable {
            introspectResponse = TestContext.provider.newIntrospectResponse(introspectRequest!!)
        }
        if (params.stageTwoThrows != null) {
            assertThrows(params.stageTwoThrows, stageTwo)
            return
        } else {
            assertDoesNotThrow(stageTwo)
        }

        assertNotNull(introspectResponse)

        params.finalAssert?.invoke(introspectResponse!!)
    }

    @AfterEach
    fun cleanUp() {
        TestContext.memoryStorage.clearAll()
    }

    companion object {
        @JvmStatic
        fun params(): List<Arguments> {
            return listOf(
                    Arguments.of(
                            "basic auth client introspect successfully",
                            TestParam(
                                    accessTokenGen = {
                                        TestContext.generateAccessToken().also {
                                            TestContext.memoryStorage.createAccessTokenSession(
                                                    it, mock(OAuthRequest::class.java).also { `when`(it.getId()).thenReturn("mock-id") })
                                        }.let {
                                            listOf(it)
                                        }
                                    },
                                    httpStub = { h: HttpRequestReader, _: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:s3cret".toByteArray()))
                                    },
                                    httpBodyParams = mutableMapOf(
                                            PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
                                    ),
                                    finalAssert = { r: IntrospectResponse ->
                                        assertTrue(r.isActive())
                                        assertNotNull(r.getAccessRequest())
                                        assertEquals(TokenType.AccessToken, r.getTokenType())
                                        r.getAccessRequest()!!.run {
                                            assertNotNull(getSession())
                                            assertTrue(getGrantedScopes().containsAll(listOf("foo", "bar")))
                                            assertEquals("test-case", getSession()!!.getSubject())
                                            assertNotNull(getSession()!!.getExpiry(TokenType.AccessToken))
                                        }
                                    }
                            )
                    ),

                    Arguments.of(
                            "should complete introspection without hint",
                            TestParam(
                                    accessTokenGen = {
                                        TestContext.generateAccessToken().also {
                                            TestContext.memoryStorage.createAccessTokenSession(
                                                    it, mock(OAuthRequest::class.java).also { `when`(it.getId()).thenReturn("mock-id") })
                                        }.let {
                                            listOf(it)
                                        }
                                    },
                                    httpStub = { h: HttpRequestReader, _: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:s3cret".toByteArray()))
                                    },
                                    httpBodyParams = mutableMapOf(),
                                    finalAssert = { r: IntrospectResponse ->
                                        assertTrue(r.isActive())
                                        assertNotNull(r.getAccessRequest())
                                        assertEquals(TokenType.AccessToken, r.getTokenType())
                                        r.getAccessRequest()!!.run {
                                            assertNotNull(getSession())
                                            assertTrue(getGrantedScopes().containsAll(listOf("foo", "bar")))
                                            assertEquals("test-case", getSession()!!.getSubject())
                                            assertNotNull(getSession()!!.getExpiry(TokenType.AccessToken))
                                        }
                                    }
                            )
                    ),

                    Arguments.of(
                            "should complete introspection without wrong hint",
                            TestParam(
                                    accessTokenGen = {
                                        TestContext.generateAccessToken().also {
                                            TestContext.memoryStorage.createAccessTokenSession(
                                                    it, mock(OAuthRequest::class.java).also { `when`(it.getId()).thenReturn("mock-id") })
                                        }.let {
                                            listOf(it)
                                        }
                                    },
                                    httpStub = { h: HttpRequestReader, _: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:s3cret".toByteArray()))
                                    },
                                    httpBodyParams = mutableMapOf(
                                            PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsRefreshToken.specValue)
                                    ),
                                    finalAssert = { r: IntrospectResponse ->
                                        assertTrue(r.isActive())
                                        assertNotNull(r.getAccessRequest())
                                        assertEquals(TokenType.AccessToken, r.getTokenType())
                                        r.getAccessRequest()!!.run {
                                            assertNotNull(getSession())
                                            assertTrue(getGrantedScopes().containsAll(listOf("foo", "bar")))
                                            assertEquals("test-case", getSession()!!.getSubject())
                                            assertNotNull(getSession()!!.getExpiry(TokenType.AccessToken))
                                        }
                                    }
                            )
                    ),

                    Arguments.of(
                            "jwt auth client introspect successfully",
                            TestParam(
                                    accessTokenGen = {
                                        mutableListOf<AccessToken>().also {
                                            TestContext.generateAccessToken().also {
                                                TestContext.memoryStorage.createAccessTokenSession(
                                                        it, mock(OAuthRequest::class.java).also { `when`(it.getId()).thenReturn("mock-id-1") })
                                            }.run { it.add(this) }
                                            TestContext.generateAccessToken().also {
                                                TestContext.memoryStorage.createAccessTokenSession(it, mock(OAuthRequest::class.java).also {
                                                    `when`(it.getId()).thenReturn("mock-id-2")
                                                    `when`(it.getClient()).then {
                                                        TestContext.clientManager.getClient("foo")
                                                    }
                                                })
                                            }.run { it.add(this) }
                                        }
                                    },
                                    httpStub = { h: HttpRequestReader, tokens: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Bearer ${tokens[1].token}")
                                    },
                                    httpBodyParams = mutableMapOf(
                                            PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
                                    ),
                                    finalAssert = { r: IntrospectResponse ->
                                        assertTrue(r.isActive())
                                        assertNotNull(r.getAccessRequest())
                                        assertEquals(TokenType.AccessToken, r.getTokenType())
                                        r.getAccessRequest()!!.run {
                                            assertNotNull(getSession())
                                            assertTrue(getGrantedScopes().containsAll(listOf("foo", "bar")))
                                            assertEquals("test-case", getSession()!!.getSubject())
                                            assertNotNull(getSession()!!.getExpiry(TokenType.AccessToken))
                                        }
                                    }
                            )
                    ),

                    Arguments.of(
                            "basic auth should fail with invalid secret",
                            TestParam(
                                    accessTokenGen = {
                                        TestContext.generateAccessToken().also {
                                            TestContext.memoryStorage.createAccessTokenSession(
                                                    it, mock(OAuthRequest::class.java).also { `when`(it.getId()).thenReturn("mock-id") })
                                        }.let {
                                            listOf(it)
                                        }
                                    },
                                    httpStub = { h: HttpRequestReader, _: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:invalid".toByteArray()))
                                    },
                                    httpBodyParams = mutableMapOf(
                                            PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
                                    ),
                                    stageOneThrows = InvalidClientException.AuthenticationFailed::class.java
                            )
                    ),

                    Arguments.of(
                            "jwt auth should fail with invalid jwt",
                            TestParam(
                                    accessTokenGen = {
                                        mutableListOf<AccessToken>().also {
                                            TestContext.generateAccessToken().also {
                                                TestContext.memoryStorage.createAccessTokenSession(
                                                        it, mock(OAuthRequest::class.java).also { `when`(it.getId()).thenReturn("mock-id-1") })
                                            }.run { it.add(this) }
                                        }
                                    },
                                    httpStub = { h: HttpRequestReader, _: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Bearer jwt")
                                    },
                                    httpBodyParams = mutableMapOf(
                                            PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
                                    ),
                                    stageOneThrows = InvalidClientException.AuthenticationFailed::class.java
                            )
                    ),

                    Arguments.of(
                            "should return nothing if there's no record",
                            TestParam(
                                    refreshTokenGen = { listOf(TestContext.generateRefreshToken()) },
                                    httpStub = { h: HttpRequestReader, _: List<AccessToken> ->
                                        `when`(h.method())
                                                .thenReturn("POST")
                                        `when`(h.getHeader("Authorization"))
                                                .thenReturn("Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:s3cret".toByteArray()))
                                    },
                                    httpBodyParams = mutableMapOf(
                                            PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsRefreshToken.specValue)
                                    ),
                                    finalAssert = { r: IntrospectResponse ->
                                        assertFalse(r.isActive())
                                        assertNull(r.getAccessRequest())
                                    }
                            )
                    )
            )
        }
    }

    class TestParam(
            val accessTokenGen: () -> List<AccessToken> = { emptyList() },
            val refreshTokenGen: () -> List<RefreshToken> = { emptyList() },
            val httpStub: (HttpRequestReader, List<AccessToken>) -> Unit,
            val httpBodyParams: MutableMap<String, List<String>> = mutableMapOf(),
            val stageOneThrows: Class<out Throwable>? = null,
            val stageTwoThrows: Class<out Throwable>? = null,
            val finalAssert: ((IntrospectResponse) -> Unit)? = null
    )

    private object TestContext {
        val memoryStorage by lazy {
            MemoryStorage()
        }

        val testJwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.use = Use.SIGNATURE
                it.keyId = "test-key"
            }
        }

        val hmacKey: SecretKey by lazy { KeyGenerator.getInstance("AES").generateKey() }

        val jwtRs256 = JwtRs256(testJwk)

        val accessTokenStrategy: AccessTokenStrategy = JwtAccessTokenStrategy(jwtRs256, "test-issuer")

        val refreshTokenStrategy: RefreshTokenStrategy = HmacRefreshTokenStrategy(
                hmac = HmacSha256(secretKey = hmacKey))

        val passwordEncoder = BCryptPasswordEncoder()

        val clientManager: ClientManager = mock(ClientManager::class.java).also {
            `when`(it.getClient("foo")).thenReturn(DefaultOAuthClient(
                    id = "foo",
                    secret = passwordEncoder.encode("s3cret").toByteArray(StandardCharsets.UTF_8)
            ))
            `when`(it.getClient("bar")).thenThrow(InvalidClientException.NotFound::class.java)
        }

        val basicClientAuthenticator = ClientSecretBasicAuthenticator(clientManager, passwordEncoder)

        val preInspectClientAuthenticator = ClientBearerPreIntrospectionAuthenticator(
                accessTokenStorage = memoryStorage, accessTokenStrategy = accessTokenStrategy
        )

        val chainedClientAuthenticator = ClientAuthenticator.customChain(
                basicClientAuthenticator, preInspectClientAuthenticator
        )

        val accessTokenJwtIntrospectHandler: IntrospectEndpointHandler = AccessTokenJwtIntrospectHandler(
                jwtRs256, "test-issuer"
        )

        val refreshTokenIntrospectHandler: IntrospectEndpointHandler = RefreshTokenStorageIntrospectHandler(
                refreshTokenStorage = memoryStorage, refreshTokenStrategy = refreshTokenStrategy
        )

        val chainedIntrospectHandler: IntrospectEndpointHandler = IntrospectEndpointHandler.with(
                accessTokenJwtIntrospectHandler, refreshTokenIntrospectHandler
        )

        val provider: IntrospectionProvider = DefaultIntrospectionProvider(
                clientAuthenticator = chainedClientAuthenticator,
                introspectHandler = chainedIntrospectHandler,
                jsonEncoder = mock(JsonEncoder::class.java)
        )

        private fun sampleAccessRequest(): AccessRequest {
            return DefaultAccessRequest.Builder().also {
                it.addScopes("foo", "bar")
                it.addGrantedScopes("foo", "bar")
                it.client = TestContext.clientManager.getClient("foo")
                it.session = DefaultJwtSession(username = "test-case", subject = "test-case", claims = JwtClaims().also {
                    it.setScopes(listOf("foo", "bar"))
                }).also {
                    it.setExpiry(TokenType.AccessToken, LocalDateTime.now().plusDays(1))
                }
            }.build() as AccessRequest
        }

        fun generateAccessToken(): AccessToken {
            return TestContext.accessTokenStrategy.generateNewAccessToken(sampleAccessRequest())
        }

        fun generateRefreshToken(): RefreshToken {
            return TestContext.refreshTokenStrategy.generateNewRefreshToken(sampleAccessRequest())
        }
    }
}