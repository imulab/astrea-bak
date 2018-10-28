package io.imulab.astrea.authorize

import io.imulab.astrea.HttpClient
import io.imulab.astrea.HttpRequestReader
import io.imulab.astrea.UrlValues
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.DefaultOidcClient
import io.imulab.astrea.error.IllegalRedirectUriException
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.oauth.ResponseType
import io.imulab.astrea.oauth.SigningAlgorithm
import io.imulab.astrea.oauth.StringEqualityScopeStrategy
import org.jose4j.jwk.*
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.InvalidJwtException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable
import org.mockito.ArgumentMatchers
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.mockito.invocation.InvocationOnMock

class NewAuthorizeRequestTest {

    companion object {

        val keySet: JsonWebKeySet = JsonWebKeySet()
        lateinit var firstKey: JsonWebKey
        lateinit var secondKey: JsonWebKey

        /**
         * Prepares two RSA-2048 keys called 'first' and 'second', and add them to [keySet].
         */
        @JvmStatic
        @BeforeAll
        fun beforeAll() {
            firstKey = RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "first"
                it.use = Use.SIGNATURE
            }
            secondKey = RsaJwkGenerator.generateJwk(2048).also {
                it.keyId = "second"
                it.use = Use.SIGNATURE
            }
            keySet.addJsonWebKey(firstKey)
            keySet.addJsonWebKey(secondKey)
        }
    }

    /**
     * Test with a proper OAuth request.
     */
    @Test
    fun `proper oauth only request should be parsed`() {
        val httpRequestReader = mockHttpRequestReader(mapOf(
                "client_id" to listOf("foo"),
                "redirect_uri" to listOf("https://test.com/callback"),
                "scope" to listOf("books"),
                "response_type" to listOf("code"),
                "state" to listOf("1234567890")
        ))
        val provider = mockedProvider()

        provider.newAuthorizeRequest(httpRequestReader).also {
            assertNotNull(it.getId())
            assertEquals("foo", it.getClient().getId())
            assertTrue(it.isRedirectUriValid())
            assertEquals("https://test.com/callback", it.getRedirectUri())
            assertIterableEquals(listOf("books"), it.getRequestScopes())
            assertIterableEquals(setOf(ResponseType.Code), it.getResponseTypes())
            assertEquals("1234567890", it.getState())
            assertTrue(it.getGrantedScopes().isEmpty())
            assertNull(it.getSession())
        }
    }

    /**
     * Test with a bad OAuth request (redirect_uri not registered)
     */
    @Test
    fun `oauth request with unregistered redirection uri should fail`() {
        val httpRequestReader = mockHttpRequestReader(mapOf(
                "client_id" to listOf("foo"),
                "redirect_uri" to listOf("https://test.com/unregistered-callback"),
                "scope" to listOf("books"),
                "response_type" to listOf("code"),
                "state" to listOf("1234567890")
        ))
        val provider = mockedProvider()
        val shouldFail = Executable { provider.newAuthorizeRequest(httpRequestReader) }
        assertThrows(IllegalRedirectUriException::class.java, shouldFail)
    }

    /**
     * Test with a proper OIDC request.
     */
    @Test
    fun `proper oidc request should be parsed`() {
        val jws = JsonWebSignature().also {
            it.payload = JwtClaims().also {
                it.issuer = "bar"
                it.audience = mutableListOf("test")
                it.setExpirationTimeMinutesInTheFuture(10f)
                it.setGeneratedJwtId()
                it.setIssuedAtToNow()
                it.setNotBeforeMinutesInThePast(2f)
                it.setStringListClaim("scope", "email")
            }.toJson()
            it.key = (firstKey as RsaJsonWebKey).rsaPrivateKey
            it.keyIdHeaderValue = "first"
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
        }
        val httpRequestReader = mockHttpRequestReader(mapOf(
                "client_id" to listOf("bar"),
                "redirect_uri" to listOf("https://test.com/callback"),
                "scope" to listOf("books openid"),
                "response_type" to listOf("code id_token"),
                "state" to listOf("1234567890"),
                "request" to listOf(jws.compactSerialization)
        ))
        val provider = mockedProvider()

        provider.newAuthorizeRequest(httpRequestReader).also {
            assertNotNull(it.getId())
            assertEquals("bar", it.getClient().getId())
            assertTrue(it.isRedirectUriValid())
            assertEquals("https://test.com/callback", it.getRedirectUri())
            assertIterableEquals(listOf("books", "openid", "email"), it.getRequestScopes())
            assertIterableEquals(setOf(ResponseType.Code, ResponseType.IdToken), it.getResponseTypes())
            assertEquals("1234567890", it.getState())
            assertTrue(it.getGrantedScopes().isEmpty())
            assertNull(it.getSession())
        }
    }

    /**
     * Test with bad OIDC request. (issuer does not match client_id)
     */
    @Test
    fun `oidc request with invalid issuer should be rejected`() {
        val jws = JsonWebSignature().also {
            it.payload = JwtClaims().also {
                it.issuer = "invalid-issuer"
                it.audience = mutableListOf("test")
                it.setExpirationTimeMinutesInTheFuture(10f)
                it.setGeneratedJwtId()
                it.setIssuedAtToNow()
                it.setNotBeforeMinutesInThePast(2f)
                it.setStringListClaim("scope", "email")
            }.toJson()
            it.key = (firstKey as RsaJsonWebKey).rsaPrivateKey
            it.keyIdHeaderValue = "first"
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
        }
        val httpRequestReader = mockHttpRequestReader(mapOf(
                "client_id" to listOf("bar"),
                "redirect_uri" to listOf("https://test.com/callback"),
                "scope" to listOf("books openid"),
                "response_type" to listOf("code id_token"),
                "state" to listOf("1234567890"),
                "request" to listOf(jws.compactSerialization)
        ))
        val provider = mockedProvider()
        val shouldFail = Executable { provider.newAuthorizeRequest(httpRequestReader) }

        assertThrows(InvalidJwtException::class.java, shouldFail)
    }

    /**
     * Test with a valid OAuth only client doing OIDC request. (client type does not match)
     */
    @Test
    fun `oauth client requesting oidc should fail`() {
        val jws = JsonWebSignature().also {
            it.payload = JwtClaims().also {
                it.issuer = "foo"
                it.audience = mutableListOf("test")
                it.setExpirationTimeMinutesInTheFuture(10f)
                it.setGeneratedJwtId()
                it.setIssuedAtToNow()
                it.setNotBeforeMinutesInThePast(2f)
                it.setStringListClaim("scope", "email")
            }.toJson()
            it.key = (firstKey as RsaJsonWebKey).rsaPrivateKey
            it.keyIdHeaderValue = "first"
            it.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
        }
        val httpRequestReader = mockHttpRequestReader(mapOf(
                "client_id" to listOf("foo"),
                "redirect_uri" to listOf("https://test.com/callback"),
                "scope" to listOf("books openid"),
                "response_type" to listOf("code id_token"),
                "state" to listOf("1234567890"),
                "request" to listOf(jws.compactSerialization)
        ))
        val provider = mockedProvider()
        val shouldFail = Executable { provider.newAuthorizeRequest(httpRequestReader) }

        assertThrows(IllegalStateException::class.java, shouldFail)
    }

    /**
     * Returns a mocked [HttpRequestReader] which uses the supplied [urlValues] as return answers. This
     * mocked version only cares about [HttpRequestReader.getForm], [HttpRequestReader.formValue], and
     * [HttpRequestReader.formValueUnescaped]. In addition, [HttpRequestReader.formValueUnescaped] uses
     * value supplied through [urlValues] directly, no addition processing is done.
     */
    private fun mockHttpRequestReader(urlValues: UrlValues): HttpRequestReader {
        val httpRequest = mock(HttpRequestReader::class.java)
        val answerFromUrlValues = { invocation: InvocationOnMock? ->
            urlValues[invocation?.getArgument(0) ?: ""]?.get(0)
        }

        `when`(httpRequest.getForm()).thenReturn(urlValues)
        `when`(httpRequest.formValueUnescaped(ArgumentMatchers.anyString())).thenAnswer(answerFromUrlValues)
        `when`(httpRequest.formValue(ArgumentMatchers.anyString())).thenAnswer(answerFromUrlValues)

        return httpRequest
    }

    /**
     * Returns a mocked [DefaultAuthorizeProvider].
     *
     * [DefaultAuthorizeProvider.clientStore] is set to a mocked [ClientManager] with two clients. One as a
     * [DefaultOAuthClient] and another as a [DefaultOidcClient]. Only properties related to this test suite
     * is set for the two clients.
     *
     * [DefaultAuthorizeProvider.httpClient] is set to a mocked [HttpClient]. No method invocation was mocked
     * as this test case does not intend to test download cases.
     *
     * [DefaultAuthorizeProvider.authorizeHandler] is set to a mocked [AuthorizeHandler]. No method invocation was mocked
     * as this test case does not intend to test actual request processing.
     *
     * [DefaultAuthorizeProvider.scopeStrategy] is set to a [StringEqualityScopeStrategy].
     *
     * [DefaultAuthorizeProvider.expectedAudience] is set to 'test'.
     */
    private fun mockedProvider(): DefaultAuthorizeProvider {
        val clientManager = mock(ClientManager::class.java)
        `when`(clientManager.getClient("foo"))
                .thenReturn(DefaultOAuthClient(
                        id = "foo",
                        secret = "s3cret".toByteArray(),
                        responseTypes = listOf(ResponseType.Code, ResponseType.Token),
                        scopes = listOf("books", "foods"),
                        redirectUris = listOf("https://test.com/callback"),
                        public = false
                ))
        `when`(clientManager.getClient("bar"))
                .thenReturn(DefaultOidcClient(
                        oauth = DefaultOAuthClient(
                                id = "bar",
                                secret = "s3cret".toByteArray(),
                                responseTypes = listOf(ResponseType.Code, ResponseType.Token, ResponseType.IdToken),
                                scopes = listOf("openid", "email", "profile", "books"),
                                redirectUris = listOf("https://test.com/callback"),
                                public = false
                        ),
                        reqObjSignAlg = SigningAlgorithm.RS256,
                        jwk = keySet
                ))

        val httpClient = mock(HttpClient::class.java)
        val authorizeHandler = mock(AuthorizeEndpointHandler::class.java)


        return DefaultAuthorizeProvider(
                authorizeHandler = authorizeHandler,
                clientStore = clientManager,
                httpClient = httpClient,
                scopeStrategy = StringEqualityScopeStrategy,
                clockSkewToleranceSecond = 30,
                minStateEntropy = 8,
                expectedAudience = "test"
        )
    }
}