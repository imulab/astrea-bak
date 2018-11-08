package io.imulab.astrea.client

import io.imulab.astrea.client.auth.ClientBearerPreIntrospectionAuthenticator
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.PARAM_TOKEN
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.error.InvalidClientException
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito

class ClientBearerPreIntrospectionAuthenticatorTest {

    @BeforeEach
    fun setup() {
        TestContext.memoryStorage.createAccessTokenSession(
                TestContext.token1,
                Mockito.mock(AccessRequest::class.java).also {
                    Mockito.`when`(it.getClient()).thenReturn(DefaultOAuthClient("c1", ByteArray(0)))
                }
        )
    }

    @Test
    fun `introspect token and bearer access token cannot be one`() {
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.getHeader("Authorization")).thenReturn("Bearer token_1")
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    PARAM_TOKEN to listOf("token_1")
            ))
        }

        assertThrows(InvalidClientException.AuthenticationFailed::class.java) {
            TestContext.clientAuthenticator.authenticate(request)
        }
    }

    @Test
    fun `authenticate should succeed when token is in storage`() {
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.getHeader("Authorization")).thenReturn("Bearer token_1")
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    PARAM_TOKEN to listOf("token_2")
            ))
        }

        val client = TestContext.clientAuthenticator.authenticate(request)
        assertEquals("c1", client.getId())
    }

    @Test
    fun `authenticate should fail when token is not in storage`() {
        val request = Mockito.mock(HttpRequestReader::class.java).also {
            Mockito.`when`(it.getHeader("Authorization")).thenReturn("Bearer token_2")
            Mockito.`when`(it.getForm()).thenReturn(mapOf(
                    PARAM_TOKEN to listOf("token_1")
            ))
        }

        assertThrows(InvalidClientException.AuthenticationFailed::class.java) {
            TestContext.clientAuthenticator.authenticate(request)
        }
    }

    @AfterEach
    fun cleanUp() {
        TestContext.memoryStorage.clearAll()
    }

    private object TestContext {

        private val testJwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.use = Use.SIGNATURE
                it.keyId = "test-key"
            }
        }

        val jwtRs256 = JwtRs256(testJwk)

        val memoryStorage by lazy { MemoryStorage() }

        val token1 = AccessToken("token_1", "sig_1")
        val token2 = AccessToken("token_2", "sig_2")

        val accessTokenStrategy: AccessTokenStrategy = Mockito.mock(AccessTokenStrategy::class.java).also {
            Mockito.`when`(it.fromRaw(token1.token)).thenReturn(token1)
            Mockito.`when`(it.fromRaw(token2.token)).thenReturn(token2)
        }

        val clientAuthenticator = ClientBearerPreIntrospectionAuthenticator(
                accessTokenStorage = memoryStorage, accessTokenStrategy = accessTokenStrategy)
    }
}