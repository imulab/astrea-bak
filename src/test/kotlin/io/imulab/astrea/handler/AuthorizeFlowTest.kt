package io.imulab.astrea.handler

import io.imulab.astrea.authorize.*
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.crypt.HmacSha256Strategy
import io.imulab.astrea.oauth.DefaultOAuthSession
import io.imulab.astrea.oauth.GrantType
import io.imulab.astrea.oauth.ResponseType
import io.imulab.astrea.oauth.StringEqualityScopeStrategy
import io.imulab.astrea.singleValue
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import javax.crypto.KeyGenerator

class AuthorizeFlowTest {

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
            it.session = DefaultOAuthSession()
        }.build() as AuthorizeRequest
        val response = DefaultAuthorizeResponse()

        flow.handleAuthorizeRequest(request, response)

        assertTrue(request.hasAllResponseTypesBeenHandled())
        assertTrue(response.getCode().isNotBlank())
        assertEquals(request.getState(), response.getQueries().singleValue("state"))
        assertEquals("foo", response.getQueries().singleValue("scope"))
    }

    /**
     * Returns an [AuthorizeFlow] whose really set parameters are only those pertaining the first leg
     * of the authorize flow (namely issuing the authorize code). Any other parameters (i.e. related to
     * exchanging for an token) can either be mocked or set, whichever is easier.
     */
    private fun getAuthorizeFlowFirstLeg(): AuthorizeFlow =
            AuthorizeFlow(
                    scopeStrategy = StringEqualityScopeStrategy,
                    authorizeCodeStorage = mockAuthorizeCodeStorage(),
                    authorizeCodeStrategy = hmacAuthorizeCodeStrategy()
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
            mock(AuthorizeCodeStorage::class.java)

    /**
     * https://medium.com/@elye.project/befriending-kotlin-and-mockito-1c2e7b0ef791
     */
    private fun <T> any(): T = null as T
}