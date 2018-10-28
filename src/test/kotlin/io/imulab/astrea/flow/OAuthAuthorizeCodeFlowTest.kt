package io.imulab.astrea.flow

import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.ResponseType
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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import javax.crypto.KeyGenerator

class OAuthAuthorizeCodeFlowTest {

    @Test
    fun `handle proper authorize request`() {
        val flow = getAuthorizeFlowFirstLeg()
        val request = DefaultAuthorizeRequest.Builder().also {
            it.client = getClient()
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
                    scopeStrategy = StringEqualityScopeStrategy,
                    authorizeCodeStorage = mockAuthorizeCodeStorage(),
                    authorizeCodeStrategy = hmacAuthorizeCodeStrategy(),
                    accessTokenStorage = mock(AccessTokenStorage::class.java),
                    accessTokenStrategy = mock(AccessTokenStrategy::class.java),
                    refreshTokenStorage = mock(RefreshTokenStorage::class.java),
                    refreshTokenStrategy = mock(RefreshTokenStrategy::class.java)
            )

    private fun getClient(): OAuthClient =
            DefaultOAuthClient(
                    id = "test-client",
                    secret = "s3cret".toByteArray(),
                    redirectUris = listOf("https://test.com/callback"),
                    scopes = listOf("foo", "bar"),
                    responseTypes = listOf(ResponseType.Code, ResponseType.Token),
                    grantTypes = listOf(GrantType.AuthorizationCode)
            )

    private fun hmacAuthorizeCodeStrategy(): AuthorizeCodeStrategy =
            HmacSha256Strategy(
                    secretKey = KeyGenerator.getInstance("AES").generateKey()
            )

    private fun mockAuthorizeCodeStorage(): AuthorizeCodeStorage =
            mock(AuthorizeCodeStorage::class.java).also {
                //                `when`(it.getAuthorizeCodeSession(any(), any())).thenReturn(
//                        DefaultAuthorizeRequest.Builder().also {
//
//                        }.build()
//                )
            }

    /**
     * https://medium.com/@elye.project/befriending-kotlin-and-mockito-1c2e7b0ef791
     */
    private fun <T> any(): T = null as T
}