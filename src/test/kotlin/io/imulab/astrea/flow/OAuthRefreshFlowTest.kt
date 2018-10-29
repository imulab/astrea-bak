package io.imulab.astrea.flow

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.ClientIdentityMismatchException
import io.imulab.astrea.error.InvalidRefreshTokenException
import io.imulab.astrea.handler.flow.OAuthRefreshFlow
import io.imulab.astrea.token.AccessToken
import io.imulab.astrea.token.RefreshToken
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.HmacSha256Strategy
import io.imulab.astrea.token.strategy.impl.JwtRs256Strategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.LocalDateTime
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class OAuthRefreshFlowTest {

    @BeforeEach
    fun prepare() {
        TestContext.also {
            it.memoryStore.createAccessTokenSession(it.preBakedAccessToken, it.preBakedAccessRequest)
            it.memoryStore.createRefreshTokenSession(it.preBakedRefreshToken, it.preBakedAccessRequest)
        }
    }

    @AfterEach
    fun clean() {
        TestContext.memoryStore.clearAll()
    }

    @Test
    fun `valid request should get new access token`() {
        val flow = OAuthRefreshFlow(
                accessTokenStrategy = TestContext.accessTokenStrategy,
                refreshTokenStrategy = TestContext.refreshTokenStrategy,
                tokenRevocationStorage = TestContext.memoryStore
        )

        val request = DefaultAccessRequest.Builder().also {
            it.setId("refresh-request")
            it.addGrantType(GrantType.RefreshToken)
            it.setForm("refresh_token", TestContext.preBakedRefreshToken.token)
            it.setClient(TestContext.preBakedClient)
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setGeneratedJwtId()
            }))
        }.build() as AccessRequest

        val response = DefaultAccessResponse()

        assertTrue(flow.handleAccessRequest(request))
        assertTrue(flow.populateAccessResponse(request, response))

        assertTrue(response.getAccessToken().isNotEmpty())
        assertNotEquals(TestContext.preBakedAccessToken.token, response.getAccessToken())
        assertEquals(TokenType.Bearer, response.getTokenType())

        assertTrue(response.getExtra("expires_in").toString().toLong() > 0)
        assertEquals("bar foo offline", response.getExtra("scope").toString().split(" ").sorted().joinToString(" "))

        assertTrue(response.getExtra("refresh_token").toString().isNotEmpty())
        assertNotEquals(TestContext.preBakedRefreshToken.token, response.getExtra("refresh_token").toString())
    }

    @Test
    fun `invalid refresh token should be rejected`() {
        val flow = OAuthRefreshFlow(
                accessTokenStrategy = TestContext.accessTokenStrategy,
                refreshTokenStrategy = TestContext.refreshTokenStrategy,
                tokenRevocationStorage = TestContext.memoryStore
        )

        val request = DefaultAccessRequest.Builder().also {
            it.setId("refresh-request")
            it.addGrantType(GrantType.RefreshToken)
            it.setForm("refresh_token", "invalid-refresh-token")
            it.setClient(TestContext.preBakedClient)
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setGeneratedJwtId()
            }))
        }.build() as AccessRequest

        assertThrows(InvalidRefreshTokenException::class.java) {
            flow.handleAccessRequest(request)
        }
    }

    @Test
    fun `a different client false claiming this refresh token should fail`() {
        val flow = OAuthRefreshFlow(
                accessTokenStrategy = TestContext.accessTokenStrategy,
                refreshTokenStrategy = TestContext.refreshTokenStrategy,
                tokenRevocationStorage = TestContext.memoryStore
        )

        val request = DefaultAccessRequest.Builder().also {
            it.setId("refresh-request")
            it.addGrantType(GrantType.RefreshToken)
            it.setForm("refresh_token", TestContext.preBakedRefreshToken.token)
            it.setClient(DefaultOAuthClient(
                    id = "a-different-client",
                    secret = "s3cret".toByteArray(),
                    grantTypes = listOf(GrantType.RefreshToken)
            ))
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setGeneratedJwtId()
            }))
        }.build() as AccessRequest

        assertThrows(ClientIdentityMismatchException::class.java) {
            flow.handleAccessRequest(request)
        }
    }

    private object TestContext {

        val jwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "test-key"
                it.use = Use.SIGNATURE
            }
        }

        val hmacKey: SecretKey by lazy { KeyGenerator.getInstance("AES").generateKey() }

        val accessTokenStrategy: AccessTokenStrategy = JwtRs256Strategy(issuer = "test", jwk = jwk)

        val refreshTokenStrategy: RefreshTokenStrategy = HmacSha256Strategy(hmacKey)

        val memoryStore: MemoryStorage by lazy { MemoryStorage() }

        val preBakedClient: OAuthClient = DefaultOAuthClient(
                id = "pre-baked",
                secret = "s3cret".toByteArray(),
                grantTypes = listOf(GrantType.RefreshToken, GrantType.AuthorizationCode),
                scopes = listOf("foo", "bar", "offline")
        )

        val preBakedAccessRequest: AccessRequest by lazy {
            DefaultAccessRequest.Builder().also {
                it.setId("pre-baked")
                it.addGrantedScopes("foo", "bar", "offline")
                it.setClient(preBakedClient)
                it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                    it.setGeneratedJwtId()
                }).also {
                    it.setExpiry(TokenType.AccessToken, LocalDateTime.now().plusDays(1))
                })
            }.build() as AccessRequest
        }

        val preBakedAccessToken: AccessToken by lazy {
            accessTokenStrategy.generateNewAccessToken(preBakedAccessRequest)
        }

        val preBakedRefreshToken: RefreshToken by lazy {
            refreshTokenStrategy.generateNewRefreshToken(preBakedAccessRequest)
        }
    }
}