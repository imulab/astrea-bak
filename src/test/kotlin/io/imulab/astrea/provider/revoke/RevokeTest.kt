package io.imulab.astrea.provider.revoke

import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.auth.ClientSecretBasicAuthenticator
import io.imulab.astrea.crypt.BCryptPasswordEncoder
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.PARAM_TOKEN_TYPE_HINT
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.TokenTypeHint
import io.imulab.astrea.domain.extension.setScopes
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.OAuthRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.error.InvalidGrantException
import io.imulab.astrea.handler.RevocationEndpointHandler
import io.imulab.astrea.handler.revoke.AccessTokenStorageRevocationHandler
import io.imulab.astrea.handler.revoke.UnsupportedRevocationHandler
import io.imulab.astrea.provider.impl.DefaultRevocationProvider
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.json.JsonEncoder
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.util.*

class RevokeTest {

    @Test
    fun `revoking non-existing token should fail gracefully`() {
        val token = TestContext.generateAccessToken().token
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.method()).thenReturn("POST")
            Mockito.`when`(it.getHeader("Authorization")).then {
                "Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:s3cret".toByteArray())
            }
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    PARAM_TOKEN to listOf(token),
                    PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
            ))
        }

        Assertions.assertThrows(RuntimeException::class.java) {
            try {
                TestContext.provider.revoke(request)
            } catch (e: Throwable) {
                Assertions.assertEquals("RevocationDidNotSucceedException", e.javaClass.simpleName)
                throw e
            }
        }
    }

    @Test
    fun `revoking a token that does not belong to requester should fail`() {
        val token = TestContext.generateAccessToken()
        TestContext.memoryStorage.createAccessTokenSession(token,
                Mockito.mock(OAuthRequest::class.java).also {
                    Mockito.`when`(it.getId()).thenReturn("mock-id-1")
                    Mockito.`when`(it.getClient()).then {
                        TestContext.clientManager.getClient("foo")
                    }
                })

        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.method()).thenReturn("POST")
            Mockito.`when`(it.getHeader("Authorization")).then {
                "Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("baz:s3cret".toByteArray())
            }
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    PARAM_TOKEN to listOf(token.token),
                    PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
            ))
        }

        Assertions.assertThrows(InvalidGrantException.ClientIdentityMismatch::class.java) {
            TestContext.provider.revoke(request)
        }
    }

    @Test
    fun `revoke an owned token should pass`() {
        val token = TestContext.generateAccessToken()
        TestContext.memoryStorage.createAccessTokenSession(token,
                Mockito.mock(OAuthRequest::class.java).also {
                    Mockito.`when`(it.getId()).thenReturn("mock-id-1")
                    Mockito.`when`(it.getClient()).then {
                        TestContext.clientManager.getClient("foo")
                    }
                })

        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.method()).thenReturn("POST")
            Mockito.`when`(it.getHeader("Authorization")).then {
                "Basic " + Base64.getUrlEncoder().withoutPadding().encodeToString("foo:s3cret".toByteArray())
            }
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    PARAM_TOKEN to listOf(token.token),
                    PARAM_TOKEN_TYPE_HINT to listOf(TokenTypeHint.HintsAccessToken.specValue)
            ))
        }

        Assertions.assertDoesNotThrow {
            TestContext.provider.revoke(request)
        }
    }

    @AfterEach
    fun cleanUp() {
        TestContext.memoryStorage.clearAll()
    }

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

        val jwtRs256 = JwtRs256(testJwk)

        val passwordEncoder = BCryptPasswordEncoder()

        val clientManager: ClientManager = Mockito.mock(ClientManager::class.java).also {
            Mockito.`when`(it.getClient("foo")).thenReturn(DefaultOAuthClient(
                    id = "foo",
                    secret = passwordEncoder.encode("s3cret").toByteArray(StandardCharsets.UTF_8)
            ))
            Mockito.`when`(it.getClient("baz")).thenReturn(DefaultOAuthClient(
                    id = "baz",
                    secret = passwordEncoder.encode("s3cret").toByteArray(StandardCharsets.UTF_8)
            ))
            Mockito.`when`(it.getClient("bar")).thenThrow(InvalidClientException.NotFound::class.java)
        }

        val basicClientAuthenticator = ClientSecretBasicAuthenticator(clientManager, passwordEncoder)

        val unsupportedRevocationHandler = UnsupportedRevocationHandler(listOf(TokenType.RefreshToken))

        val accessTokenStrategy: AccessTokenStrategy = JwtAccessTokenStrategy(jwtRs256, "test-issuer")

        val accessTokenRevocationHandler = AccessTokenStorageRevocationHandler(
                accessTokenStrategy = accessTokenStrategy,
                accessTokenStorage = memoryStorage,
                tokenRevocationStorage = memoryStorage
        )

        val revocationHandler = RevocationEndpointHandler.with(
                accessTokenRevocationHandler,
                unsupportedRevocationHandler
        )

        val provider = DefaultRevocationProvider(
                clientAuthenticator = basicClientAuthenticator,
                handler = revocationHandler,
                jsonEncoder = Mockito.mock(JsonEncoder::class.java)
        )

        private fun sampleAccessRequest(): AccessRequest {
            return DefaultAccessRequest.Builder().also {
                it.addScopes("foo", "bar")
                it.addGrantedScopes("foo", "bar")
                it.client = clientManager.getClient("foo")
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
    }
}