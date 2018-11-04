package io.imulab.astrea.flow

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.HmacSha256
import io.imulab.astrea.crypt.JwtRs256
import io.imulab.astrea.domain.*
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.error.InvalidAuthorizeCodeException
import io.imulab.astrea.handler.flow.OAuthAuthorizeCodeFlow
import io.imulab.astrea.spi.http.singleValue
import io.imulab.astrea.token.storage.impl.MemoryStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.HmacAuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.impl.HmacRefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.JwtAccessTokenStrategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class OAuthAuthorizeCodeFlowTest {

    @AfterEach
    fun afterEach() {
        TestContext.memoryStore.clearAll()
    }

    @Test
    fun `normal authorize code flow`() {
        val flow = TestContext.getFlow()

        assertDoesNotThrow {
            val authorizeResponse = testAuthorize(flow)
            val accessRequest = testHandleAccess(flow, authorizeResponse)
            testPopulateAccessResponse(flow, accessRequest)
        }
    }

    @Test
    fun `expired authorize code should fail`() {
        val flow = TestContext.getFlow()

        assertThrows(InvalidAuthorizeCodeException::class.java) {
            val authorizeResponse = testAuthorize(flow)
            TestContext.memoryStore.expireAuthorizeCode(authorizeResponse.getCode().split(".")[1])
            testHandleAccess(flow, authorizeResponse)
        }
    }

    @Test
    fun `altered authorize code should fail`() {
        val flow = TestContext.getFlow()

        assertThrows(InvalidAuthorizeCodeException::class.java) {
            val authorizeResponse = testAuthorize(flow)
            flow.handleAccessRequest(DefaultAccessRequest.Builder().also {
                it.setForm("code", "altered" + authorizeResponse.getCode())
                it.setForm("redirect_uri", "https://test.com/callback")
                it.addGrantType(GrantType.AuthorizationCode)
                it.session = DefaultSession()
                it.client = TestContext.client
            }.build() as AccessRequest)
        }
    }

    @Test
    fun `non-existing code should fail`() {
        val flow = TestContext.getFlow()

        assertThrows(InvalidAuthorizeCodeException::class.java) {
            val authorizeResponse = testAuthorize(flow)
            TestContext.memoryStore.clearAuthorizeCodes()
            testHandleAccess(flow, authorizeResponse)
        }
    }

    private fun testAuthorize(flow: OAuthAuthorizeCodeFlow): AuthorizeResponse {
        val authorizeRequest = DefaultAuthorizeRequest.Builder().also {
            it.client = TestContext.client
            it.responseTypes = mutableSetOf(ResponseType.Code)
            it.redirectUri = "https://test.com/callback"
            it.addScopes("foo", "bar", "offline")
            it.addGrantedScopes("foo", "offline")
            it.state = "1234567890"
            it.session = DefaultJwtSession.Builder().also {
                it.getClaims().setStringClaim("foo", "bar")
            }.build()
        }.build() as AuthorizeRequest
        val authorizeResponse = DefaultAuthorizeResponse()

        flow.handleAuthorizeRequest(authorizeRequest, authorizeResponse)

        assertTrue(authorizeRequest.hasAllResponseTypesBeenHandled())
        assertTrue(authorizeResponse.getCode().isNotBlank())
        assertEquals(authorizeRequest.getState(), authorizeResponse.getQueries().singleValue("state"))
        assertTrue(authorizeResponse.getQueries().singleValue("scope").split(" ").contains("foo"))
        assertTrue(authorizeResponse.getQueries().singleValue("scope").split(" ").contains("offline"))

        return authorizeResponse
    }

    private fun testHandleAccess(flow: OAuthAuthorizeCodeFlow, authorizeResponse: AuthorizeResponse): AccessRequest {
        val accessRequest = DefaultAccessRequest.Builder().also {
            it.setForm("code", authorizeResponse.getCode())
            it.setForm("redirect_uri", "https://test.com/callback")
            it.addGrantType(GrantType.AuthorizationCode)
            it.session = DefaultSession()
            it.client = TestContext.client
        }.build() as AccessRequest

        flow.handleAccessRequest(accessRequest)

        return accessRequest
    }

    private fun testPopulateAccessResponse(flow: OAuthAuthorizeCodeFlow, accessRequest: AccessRequest) {
        val accessResponse = DefaultAccessResponse()
        assertDoesNotThrow {
            flow.populateAccessResponse(accessRequest, accessResponse)
        }

        assertTrue(accessResponse.getAccessToken().isNotBlank())
        assertEquals(TokenType.Bearer, accessResponse.getTokenType())
        assertTrue(accessResponse.getExtra("refresh_token").toString().isNotBlank())
        assertTrue(accessResponse.getExtra("expires_in") as Long > 0)
    }

    /**
     * Context for this test. Defines all necessary dependencies.
     */
    private object TestContext {

        val memoryStore: MemoryStorage by lazy { MemoryStorage() }

        val jwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "test-jwk"
                it.use = Use.SIGNATURE
            }
        }

        val hmacKey: SecretKey by lazy {
            KeyGenerator.getInstance("AES").generateKey()
        }

        val authorizeCodeStrategy: AuthorizeCodeStrategy = HmacAuthorizeCodeStrategy(hmac = HmacSha256(secretKey = hmacKey))

        val accessTokenStrategy: AccessTokenStrategy = JwtAccessTokenStrategy(
                issuer = "astrea",
                jwtRs256 = JwtRs256(jwk = this.jwk)
        )

        val refreshTokenStrategy: RefreshTokenStrategy = HmacRefreshTokenStrategy(hmac = HmacSha256(secretKey = hmacKey))

        val scopeStrategy: ScopeStrategy = StringEqualityScopeStrategy

        val client: OAuthClient = DefaultOAuthClient(
                id = "test-client",
                secret = "s3cret".toByteArray(),
                redirectUris = listOf("https://test.com/callback"),
                scopes = listOf("foo", "bar", "offline"),
                responseTypes = listOf(ResponseType.Code, ResponseType.Token),
                grantTypes = listOf(GrantType.AuthorizationCode)
        )

        fun getFlow(): OAuthAuthorizeCodeFlow =
                OAuthAuthorizeCodeFlow(
                        scopeStrategy = scopeStrategy,
                        authorizeCodeStrategy = authorizeCodeStrategy,
                        authorizeCodeStorage = memoryStore,
                        accessTokenStrategy = accessTokenStrategy,
                        accessTokenStorage = memoryStore,
                        refreshTokenStrategy = refreshTokenStrategy,
                        refreshTokenStorage = memoryStore
                )

        /**
         * https://medium.com/@elye.project/befriending-kotlin-and-mockito-1c2e7b0ef791
         */
        @Suppress("unchecked_cast")
        private fun <T> anything(): T = null as T
    }
}