package io.imulab.astrea.provider.authorize

import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.error.Rfc6749Error
import io.imulab.astrea.error.Rfc6749Exception
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.provider.impl.DefaultAuthorizeProvider
import io.imulab.astrea.spi.http.HttpClient
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.json.JsonEncoder
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import java.nio.charset.StandardCharsets

class EncodeAuthorizeErrorTest {

    @Test
    fun `test encode rfc6749 authorize error as queries`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = Mockito.mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = Mockito.mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = Mockito.mock(HttpClient::class.java),
                clientStore = Mockito.mock(ClientManager::class.java),
                outputDebugInErrorResponse = true,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = Mockito.mock(AuthorizeRequest::class.java)
        Mockito.`when`(request.getRedirectUri()).thenReturn("https://test.com/callback")
        Mockito.`when`(request.isRedirectUriValid()).thenReturn(true)

        val error = object : Rfc6749Exception(
                Rfc6749Error.InvalidRequestUri,
                "test-description",
                "test-hint",
                "test-debug") {}

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeError(TestContext.httpResponseWriter(collector), request, error)

        Assertions.assertEquals("302", collector["status"])
        Assertions.assertEquals("https://test.com/callback?" +
                "status_code=${Rfc6749Error.InvalidRequestUri.statusCode}" +
                "&" +
                "debug=test-debug" +
                "&" +
                "error_description=test-description" +
                "&" +
                "hint=test-hint" +
                "&" +
                "error=${Rfc6749Error.InvalidRequestUri.specValue}", collector["header_Location"])
    }

    @Test
    fun `test encode rfc6749 authorize error as fragments`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = Mockito.mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = Mockito.mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = Mockito.mock(HttpClient::class.java),
                clientStore = Mockito.mock(ClientManager::class.java),
                outputDebugInErrorResponse = true,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = Mockito.mock(AuthorizeRequest::class.java)
        Mockito.`when`(request.getRedirectUri()).thenReturn("https://test.com/callback")
        Mockito.`when`(request.isRedirectUriValid()).thenReturn(true)
        Mockito.`when`(request.getResponseTypes()).thenReturn(setOf(ResponseType.Token))

        val error = object : Rfc6749Exception(
                Rfc6749Error.InvalidRequestUri,
                "test-description",
                "test-hint",
                "test-debug") {}

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeError(TestContext.httpResponseWriter(collector), request, error)

        Assertions.assertEquals("302", collector["status"])
        Assertions.assertEquals("https://test.com/callback#" +
                "status_code=${Rfc6749Error.InvalidRequestUri.statusCode}" +
                "&" +
                "debug=test-debug" +
                "&" +
                "error_description=test-description" +
                "&" +
                "hint=test-hint" +
                "&" +
                "error=${Rfc6749Error.InvalidRequestUri.specValue}", collector["header_Location"])
    }

    @Test
    fun `test encode generic authorize error`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = Mockito.mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = Mockito.mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = Mockito.mock(HttpClient::class.java),
                clientStore = Mockito.mock(ClientManager::class.java),
                outputDebugInErrorResponse = true,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = Mockito.mock(AuthorizeRequest::class.java)
        Mockito.`when`(request.getRedirectUri()).thenReturn("https://test.com/callback")
        Mockito.`when`(request.isRedirectUriValid()).thenReturn(true)

        val error = RuntimeException("generic")

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeError(TestContext.httpResponseWriter(collector), request, error)

        Assertions.assertEquals("302", collector["status"])
        Assertions.assertEquals("https://test.com/callback?" +
                "status_code=${Rfc6749Error.Unknown.statusCode}" +
                "&" +
                "debug=generic" +
                "&" +
                "error=${Rfc6749Error.Unknown.specValue}", collector["header_Location"])
    }

    private object TestContext {

        fun httpResponseWriter(collector: MutableMap<String, String>): HttpResponseWriter {
            return object : HttpResponseWriter {
                override fun setStatus(status: Int) {
                    collector["status"] = status.toString()
                }

                override fun setHeader(name: String, value: String) {
                    collector["header_$name"] = value
                }

                override fun writeBody(data: ByteArray) {
                    collector["body"] = String(data)
                }
            }
        }

        val testJsonEncoder: JsonEncoder by lazy {
            object : JsonEncoder {
                override fun encode(any: Any, pretty: Boolean): ByteArray {
                    return Klaxon().toJsonString(any).toByteArray(StandardCharsets.UTF_8)
                }
            }
        }
    }
}