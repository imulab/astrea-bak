package io.imulab.astrea.flow

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.StringEqualityScopeStrategy
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.DefaultAuthorizeResponse
import io.imulab.astrea.domain.session.impl.DefaultSession
import io.imulab.astrea.handler.flow.OAuthAuthorizeCodeFlow
import io.imulab.astrea.spi.singleValue
import io.imulab.astrea.token.storage.AccessTokenStorage
import io.imulab.astrea.token.storage.AuthorizeCodeStorage
import io.imulab.astrea.token.storage.RefreshTokenStorage
import io.imulab.astrea.token.strategy.AccessTokenStrategy
import io.imulab.astrea.token.strategy.AuthorizeCodeStrategy
import io.imulab.astrea.token.strategy.RefreshTokenStrategy
import io.imulab.astrea.token.strategy.impl.HmacSha256Strategy
import io.imulab.astrea.token.strategy.impl.JwtRs256Strategy
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import org.jose4j.jwk.Use
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import javax.crypto.KeyGenerator

class OAuthAuthorizeCodeFlowTest {

    /**
     * The test design is based on a narrative:
     * ----
     * One client exists:
     * - client_id = test-client
     * - secret = s3cret
     * - response_types = code, token
     * - redirect_uri = https://test.com/callback
     * - grant_types = authorization_code
     *
     *
     */

    @Test
    fun `handle proper authorize request`() {
        val flow = getAuthorizeFlowFirstLeg()
        val request = DefaultAuthorizeRequest.Builder().also {
            it.client = TestContext.client
            it.responseTypes = mutableSetOf(ResponseType.Code)
            it.redirectUri = "https://test.com/callback"
            it.addScopes("foo", "bar")
            it.addGrantedScopes("foo")
            it.state = "1234567890"
            it.session = DefaultSession()
        }.build() as AuthorizeRequest
        val response = DefaultAuthorizeResponse()

        flow.handleAuthorizeRequest(request, response)

        assertTrue(request.hasAllResponseTypesBeenHandled())
        assertTrue(response.getCode().isNotBlank())
        assertEquals(request.getState(), response.getQueries().singleValue("state"))
        assertEquals("foo", response.getQueries().singleValue("scope"))
    }

    /**
     * Returns an [OAuthAuthorizeCodeFlow] whose really set parameters are only those pertaining the first leg
     * of the authorize flow (namely issuing the authorize code). Any other parameters (i.e. related to
     * exchanging for an token) can either be mocked or set, whichever is easier.
     */
    private fun getAuthorizeFlowFirstLeg(): OAuthAuthorizeCodeFlow =
            OAuthAuthorizeCodeFlow(
                    scopeStrategy = TestContext.scopeStrategy,
                    authorizeCodeStorage = TestContext.authorizeCodeStorage,
                    authorizeCodeStrategy = TestContext.authorizeCodeStrategy,
                    accessTokenStorage = mock(AccessTokenStorage::class.java),
                    accessTokenStrategy = mock(AccessTokenStrategy::class.java),
                    refreshTokenStorage = mock(RefreshTokenStorage::class.java),
                    refreshTokenStrategy = mock(RefreshTokenStrategy::class.java)
            )

    private object TestContext {

        val scopeStrategy: ScopeStrategy = StringEqualityScopeStrategy

        val authorizeCodeStrategy: AuthorizeCodeStrategy by lazy {
            val key = KeyGenerator.getInstance("AES").generateKey()
            return@lazy HmacSha256Strategy(secretKey = key)
        }

        val authorizeCodeStorage: AuthorizeCodeStorage by lazy {
            val storage = mock(AuthorizeCodeStorage::class.java)
            // TODO
            return@lazy storage
        }

        val jwk: RsaJsonWebKey by lazy {
            RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "test-jwk"
                it.use = Use.SIGNATURE
            }
        }

        val accessTokenStrategy: AccessTokenStrategy by lazy {
            JwtRs256Strategy(
                    issuer = "astrea",
                    jwk = this.jwk
            )
        }

        val accessTokenStorage: AccessTokenStorage by lazy {
            val storage = mock(AccessTokenStorage::class.java)
            // TODO
            return@lazy storage
        }

        val refreshTokenStrategy: RefreshTokenStrategy by lazy {
            val key = KeyGenerator.getInstance("AES").generateKey()
            return@lazy HmacSha256Strategy(secretKey = key)
        }

        val refreshTokenStorage: RefreshTokenStorage by lazy {
            val storage = mock(RefreshTokenStorage::class.java)
            // TODO
            return@lazy storage
        }

        val client: OAuthClient by lazy {
            DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    redirectUris = listOf("https://test.com/callback"),
                    scopes = listOf("foo", "bar"),
                    responseTypes = listOf(ResponseType.Code, ResponseType.Token),
                    grantTypes = listOf(GrantType.AuthorizationCode)
            )
        }

        /**
         * https://medium.com/@elye.project/befriending-kotlin-and-mockito-1c2e7b0ef791
         */
        @Suppress("unchecked_cast")
        private fun <T> anything(): T = null as T
    }
}