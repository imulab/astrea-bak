package io.imulab.astrea.provider.access

import com.beust.klaxon.Converter
import com.beust.klaxon.JsonValue
import com.beust.klaxon.Klaxon
import io.imulab.astrea.client.DefaultOAuthClient
import io.imulab.astrea.client.auth.ClientAuthenticator
import io.imulab.astrea.domain.GrantType
import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.request.DefaultAccessRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.error.OAuthException
import io.imulab.astrea.handler.TokenEndpointHandler
import io.imulab.astrea.provider.impl.DefaultAccessProvider
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.json.JsonEncoder
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import java.nio.charset.StandardCharsets

class EncodeAccessErrorTest {

    @Test
    fun `test encode rfc6749 error`() {
        val provider = DefaultAccessProvider(
                clientAuthenticator = Mockito.mock(ClientAuthenticator::class.java),
                jsonEncoder = TestContext.testJsonEncoder,
                outputDebugInErrorResponse = true,
                tokenEndpointHandler = Mockito.mock(TokenEndpointHandler::class.java)
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

        val error = object : OAuthException("test-code", "test-description") {
            override fun statusCode(): Int = 400
        }

        val collector = hashMapOf<String, String>()
        provider.encodeAccessError(TestContext.httpResponseWriter(collector), request, error)

        assertEquals("400", collector["status"])
        assertEquals("application/json;charset=UTF-8", collector["header_Content-Type"])

        val json = TestContext.klaxonParser.parse<Map<String, String>>(collector["body"]!!)!!
        assertEquals("400", json["status_code"])
        assertEquals("test-description", json["error_description"])
        assertEquals("test-code", json["error"])
    }

    @Test
    fun `test encode generic access error`() {
        val provider = DefaultAccessProvider(
                clientAuthenticator = Mockito.mock(ClientAuthenticator::class.java),
                jsonEncoder = TestContext.testJsonEncoder,
                outputDebugInErrorResponse = true,
                tokenEndpointHandler = Mockito.mock(TokenEndpointHandler::class.java)
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

        val error = RuntimeException("generic")

        val collector = hashMapOf<String, String>()
        provider.encodeAccessError(TestContext.httpResponseWriter(collector), request, error)

        assertEquals("500", collector["status"])
        assertEquals("application/json;charset=UTF-8", collector["header_Content-Type"])

        val json = TestContext.klaxonParser.parse<Map<String, String>>(collector["body"]!!)!!
        assertEquals("500", json["status_code"])
        assertEquals("server_error", json["error"])
        assertEquals("generic", json["error_description"])
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