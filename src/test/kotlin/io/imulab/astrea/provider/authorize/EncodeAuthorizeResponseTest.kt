package io.imulab.astrea.provider.authorize

import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.ClientManager
import io.imulab.astrea.client.OAuthClient
import io.imulab.astrea.domain.ScopeStrategy
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.request.DefaultAuthorizeRequest
import io.imulab.astrea.domain.response.impl.DefaultAuthorizeResponse
import io.imulab.astrea.handler.AuthorizeEndpointHandler
import io.imulab.astrea.provider.impl.DefaultAuthorizeProvider
import io.imulab.astrea.spi.http.HttpClient
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.json.JsonEncoder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets

class EncodeAuthorizeResponseTest {

    @Test
    fun `encode authorize response with query`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = mock(HttpClient::class.java),
                clientStore = mock(ClientManager::class.java),
                outputDebugInErrorResponse = true,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = DefaultAuthorizeRequest.Builder().also {
            it.client = mock(OAuthClient::class.java)
            it.redirectUri = "https://test.com/callback"
            it.state = "1234567890"
        }.build() as AuthorizeRequest

        val response = DefaultAuthorizeResponse().also {
            it.addQuery("scope", "foo bar")
            it.addQuery("state", "1234567890")
        }

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeResponse(TestContext.httpResponseWriter(collector), request, response)

        assertEquals("302", collector["status"])
        assertEquals("https://test.com/callback?scope=foo+bar&state=1234567890#", collector["header_Location"])
    }

    @Test
    fun `encode authorize response with fragments`() {
        val provider = DefaultAuthorizeProvider(
                authorizeHandler = mock(AuthorizeEndpointHandler::class.java),
                scopeStrategy = mock(ScopeStrategy::class.java),
                expectedAudience = "test",
                httpClient = mock(HttpClient::class.java),
                clientStore = mock(ClientManager::class.java),
                outputDebugInErrorResponse = true,
                jsonEncoder = TestContext.testJsonEncoder
        )

        val request = DefaultAuthorizeRequest.Builder().also {
            it.client = mock(OAuthClient::class.java)
            it.redirectUri = "https://test.com/callback"
            it.state = "1234567890"
        }.build() as AuthorizeRequest

        val response = DefaultAuthorizeResponse().also {
            it.addFragment("scope", "foo bar")
            it.addFragment("state", "1234567890")
        }

        val collector = hashMapOf<String, String>()
        provider.encodeAuthorizeResponse(TestContext.httpResponseWriter(collector), request, response)

        assertEquals("302", collector["status"])
        assertEquals("https://test.com/callback#scope=foo%20bar&state=1234567890", collector["header_Location"])
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