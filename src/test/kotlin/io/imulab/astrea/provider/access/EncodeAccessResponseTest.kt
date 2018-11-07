package io.imulab.astrea.provider.access

import com.beust.klaxon.Converter
import com.beust.klaxon.JsonValue
import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.impl.DefaultAccessRequest
import io.imulab.astrea.domain.response.impl.DefaultAccessResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.provider.impl.DefaultAccessProvider
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.json.JsonEncoder
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime

class EncodeAccessResponseTest {

    @Test
    fun `encode access response`() {
        val provider = DefaultAccessProvider(
                clientAuthenticator = mock(ClientAuthenticator::class.java),
                jsonEncoder = TestContext.testJsonEncoder,
                outputDebugInErrorResponse = true,
                tokenEndpointHandler = mock(TokenEndpointHandler::class.java)
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

        val response = DefaultAccessResponse().also {
            it.setAccessToken("test-access-token")
            it.setExpiry(LocalDateTime.now().plusDays(1))
            it.setScopes(listOf("foo", "bar"))
            it.setTokenType(TokenType.Bearer)
            it.setExtra("refresh_token", "test-refresh-token")
        }

        val collector = hashMapOf<String, String>()
        provider.encodeAccessResponse(TestContext.httpResponseWriter(collector), request, response)

        assertEquals("200", collector["status"])
        assertEquals("application/json;charset=UTF-8", collector["header_Content-Type"])
        assertEquals("no-cache", collector["header_Pragma"])
        assertEquals("no-store", collector["header_Cache-Control"])

        val parsed = TestContext.klaxonParser.parse<Map<String, String>>(collector["body"]!!)!!
        assertEquals("test-access-token", parsed["access_token"])
        assertEquals("bearer", parsed["token_type"])
        assertEquals("test-refresh-token", parsed["refresh_token"])
        assertEquals("foo bar", parsed["scope"])
        assertTrue(parsed["expires_in"].toString().toLong() > 0)
    }

    private object TestContext {

        val klaxonParser: Klaxon by lazy {
            val klaxon = Klaxon()
            val converter: Converter = object : Converter {
                override fun canConvert(cls: Class<*>): Boolean = cls.isAssignableFrom(Map::class.java)

                override fun fromJson(jv: JsonValue): Any = HashMap(jv.obj)

                override fun toJson(value: Any): String {
                    throw UnsupportedOperationException("not implemented")
                }
            }
            return@lazy klaxon.converter(converter)
        }

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