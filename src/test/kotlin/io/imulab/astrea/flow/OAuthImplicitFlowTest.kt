package io.imulab.astrea.flow

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.ClientGrantTypeException
import io.imulab.astrea.error.ScopeRejectedException
import io.imulab.astrea.handler.flow.OAuthImplicitFlow
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtRs256Strategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OAuthImplicitFlowTest {

    @AfterEach
    fun clean() {
        TestContext.memoryStorage.clearAll()
    }

    @Test
    fun `implicit flow passes`() {
        val flow = OAuthImplicitFlow(
                scopeStrategy = TestContext.scopeStrategy,
                accessTokenStorage = TestContext.memoryStorage,
                accessTokenStrategy = TestContext.accessTokenStrategy
        )

        val request = DefaultAuthorizeRequest.Builder().also {
            it.addResponseTypes(ResponseType.Token)
            it.setClient(DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    scopes = listOf("foo", "bar", "zoo"),
                    grantTypes = listOf(GrantType.Implicit, GrantType.AuthorizationCode)
            ))
            it.addScopes("foo", "bar")
            it.addGrantedScopes("foo", "bar")
            it.setState("1234567890")
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setStringClaim("foo", "bar")
            }))
        }.build() as AuthorizeRequest

        val response = DefaultAuthorizeResponse()

        assertDoesNotThrow {
            flow.handleAuthorizeRequest(request, response)
        }

        assertTrue(response.getFragments().singleValue("access_token").isNotEmpty())
        assertTrue(response.getFragments().singleValue("expires_in").toLong() > 0)
        assertEquals(TokenType.Bearer.specValue, response.getFragments().singleValue("token_type"))
        assertEquals("1234567890", response.getFragments().singleValue("state"))
        assertEquals("bar foo", response.getFragments().singleValue("scope").split(" ").sorted().joinToString(" "))
    }

    @Test
    fun `client that has no right for scope shall fail`() {
        val flow = OAuthImplicitFlow(
                scopeStrategy = TestContext.scopeStrategy,
                accessTokenStorage = TestContext.memoryStorage,
                accessTokenStrategy = TestContext.accessTokenStrategy
        )

        val request = DefaultAuthorizeRequest.Builder().also {
            it.addResponseTypes(ResponseType.Token)
            it.setClient(DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    scopes = listOf("foo"),
                    grantTypes = listOf(GrantType.Implicit, GrantType.AuthorizationCode)
            ))
            it.addScopes("foo", "bar")
            it.addGrantedScopes("foo", "bar")
            it.setState("1234567890")
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setStringClaim("foo", "bar")
            }))
        }.build() as AuthorizeRequest

        val response = DefaultAuthorizeResponse()

        assertThrows(ScopeRejectedException::class.java) {
            flow.handleAuthorizeRequest(request, response)
        }
    }

    @Test
    fun `client not capable of implicit flow shall fail`() {
        val flow = OAuthImplicitFlow(
                scopeStrategy = TestContext.scopeStrategy,
                accessTokenStorage = TestContext.memoryStorage,
                accessTokenStrategy = TestContext.accessTokenStrategy
        )

        val request = DefaultAuthorizeRequest.Builder().also {
            it.addResponseTypes(ResponseType.Token)
            it.setClient(DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    scopes = listOf("foo", "bar", "zoo"),
                    grantTypes = listOf(GrantType.AuthorizationCode)
            ))
            it.addScopes("foo", "bar")
            it.addGrantedScopes("foo", "bar")
            it.setState("1234567890")
            it.setSession(DefaultJwtSession(claims = JwtClaims().also {
                it.setStringClaim("foo", "bar")
            }))
        }.build() as AuthorizeRequest

        val response = DefaultAuthorizeResponse()

        assertThrows(ClientGrantTypeException::class.java) {
            flow.handleAuthorizeRequest(request, response)
        }
    }

    private object TestContext {

        val jwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "test-key"
                it.use = Use.SIGNATURE
            }
        }

        val accessTokenStrategy: AccessTokenStrategy = JwtRs256Strategy(
                issuer = "test",
                jwk = this.jwk
        )

        val memoryStorage by lazy { MemoryStorage() }

        val scopeStrategy = StringEqualityScopeStrategy
    }
}