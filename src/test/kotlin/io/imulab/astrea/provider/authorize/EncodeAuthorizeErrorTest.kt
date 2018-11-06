package io.imulab.astrea.provider.authorize

import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.domain.ResponseType
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.error.OAuthException
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
                outputDebugInErrorResponse = false,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = Mockito.mock(AuthorizeRequest::class.java)
        Mockito.`when`(request.getRedirectUri()).thenReturn("https://test.com/callback")
        Mockito.`when`(request.isRedirectUriValid()).thenReturn(true)

        val error = object : OAuthException("test-code", "test-description") {
            override fun statusCode(): Int = 400
        }

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeError(TestContext.httpResponseWriter(collector), request, error)

        Assertions.assertEquals("302", collector["status"])
        Assertions.assertEquals("https://test.com/callback?" +
                "status_code=400" +
                "&" +
                "error_description=test-description" +
                "&" +
                "error=test-code", collector["header_Location"])
    }

    @Test
    fun `test encode rfc6749 authorize error as fragments`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = Mockito.mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = Mockito.mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = Mockito.mock(HttpClient::class.java),
                clientStore = Mockito.mock(ClientManager::class.java),
                outputDebugInErrorResponse = false,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = Mockito.mock(AuthorizeRequest::class.java)
        Mockito.`when`(request.getRedirectUri()).thenReturn("https://test.com/callback")
        Mockito.`when`(request.isRedirectUriValid()).thenReturn(true)
        Mockito.`when`(request.getResponseTypes()).thenReturn(setOf(ResponseType.Token))

        val error = object : OAuthException("test-code", "test-description") {
            override fun statusCode(): Int = 400
        }

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeError(TestContext.httpResponseWriter(collector), request, error)

        Assertions.assertEquals("302", collector["status"])
        Assertions.assertEquals("https://test.com/callback#" +
                "status_code=400" +
                "&" +
                "error_description=test-description" +
                "&" +
                "error=test-code", collector["header_Location"])
    }

    @Test
    fun `test encode generic authorize error`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = Mockito.mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = Mockito.mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = Mockito.mock(HttpClient::class.java),
                clientStore = Mockito.mock(ClientManager::class.java),
                outputDebugInErrorResponse = false,
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
                "status_code=500" +
                "&" +
                "error_description=generic" +
                "&" +
                "error=server_error", collector["header_Location"])
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