package io.imulab.astrea.flow

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.ClientGrantTypeException
import io.imulab.astrea.handler.flow.OAuthClientCredentialsFlow
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito

class OAuthClientCredentialFlowTest {

    @AfterEach
    fun clean() {
        TestContext.memoryStore.clearAll()
    }

    @Test
    fun `client credential shall pass`() {
        val flow = OAuthClientCredentialsFlow(
                scopeStrategy = TestContext.scopeStrategy,
                accessTokenStrategy = TestContext.accessTokenStrategy,
                accessTokenStorage = TestContext.memoryStore,
                refreshTokenStorage = Mockito.mock(RefreshTokenStorage::class.java),
                refreshTokenStrategy = Mockito.mock(RefreshTokenStrategy::class.java)
        )

        val request = DefaultAccessRequest.Builder().also {
            it.addGrantType(GrantType.ClientCredentials)
            it.setClient(DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    scopes = listOf("foo", "bar"),
                    grantTypes = listOf(GrantType.ClientCredentials)
            ))
            it.addScopes("foo", "bar")
            it.addGrantedScopes("foo", "bar")
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setGeneratedJwtId()
            }))
        }.build() as AccessRequest

        val response = DefaultAccessResponse()

        assertTrue(flow.supports(request))
        assertDoesNotThrow {
            flow.handleAccessRequest(request)
            flow.populateAccessResponse(request, response)
        }

        assertTrue(response.getAccessToken().isNotBlank())
        assertEquals(TokenType.Bearer, response.getTokenType())
        assertEquals("bar foo", response.getExtra("scope").toString().split(" ").sorted().joinToString(" "))
        assertTrue(response.getExtra("expires_in").toString().toLong() > 0)
    }

    @Test
    fun `client without client credential grant type shall fail`() {
        val flow = OAuthClientCredentialsFlow(
                scopeStrategy = TestContext.scopeStrategy,
                accessTokenStrategy = TestContext.accessTokenStrategy,
                accessTokenStorage = TestContext.memoryStore,
                refreshTokenStorage = Mockito.mock(RefreshTokenStorage::class.java),
                refreshTokenStrategy = Mockito.mock(RefreshTokenStrategy::class.java)
        )

        val request = DefaultAccessRequest.Builder().also {
            it.addGrantType(GrantType.ClientCredentials)
            it.setClient(DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    scopes = listOf("foo", "bar"),
                    grantTypes = listOf(GrantType.Password)
            ))
            it.addScopes("foo", "bar")
            it.addGrantedScopes("foo", "bar")
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setGeneratedJwtId()
            }))
        }.build() as AccessRequest

        assertThrows(ClientGrantTypeException::class.java) {
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

        val scopeStrategy = StringEqualityScopeStrategy

        val memoryStore: MemoryStorage by lazy { MemoryStorage() }

        val accessTokenStrategy: AccessTokenStrategy = JwtAccessTokenStrategy(
                issuer = "test",
                jwtRs256 = JwtRs256(jwk = this.jwk)
        )
    }
}