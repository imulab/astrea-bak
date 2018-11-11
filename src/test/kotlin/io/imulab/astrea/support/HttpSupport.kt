package io.imulab.astrea.support

import com.beust.klaxon.Converter
import com.beust.klaxon.JsonValue
import com.beust.klaxon.Klaxon
import io.imulab.astrea.domain.SPACE
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.astrea.spi.http.UrlValues
import org.assertj.core.api.Assertions.assertThat
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.util.*

object HttpSupport {

    fun jsonDeserializer(): Klaxon {
        val klaxon = Klaxon()
        val converter: Converter = object : Converter {
            override fun canConvert(cls: Class<*>): Boolean = cls.isAssignableFrom(Map::class.java)

            override fun fromJson(jv: JsonValue): Any = HashMap(jv.obj)

            override fun toJson(value: Any): String {
                throw UnsupportedOperationException("not implemented")
            }
        }
        return klaxon.converter(converter)
    }

    fun request(method: String = "POST",
                headers: Map<String, String> = emptyMap(),
                forms: UrlValues = emptyMap()): HttpRequestReader {
        val reader = mock(HttpRequestReader::class.java)
        `when`(reader.method()).thenReturn(method)
        headers.forEach { t, u -> `when`(reader.getHeader(t)).thenReturn(u) }
        `when`(reader.getForm()).thenReturn(forms)
        return reader
    }

    fun basicAuthHeader(username: String, password: String): String {
        return "Basic" + SPACE + Base64.getUrlEncoder().withoutPadding().encodeToString("$username:$password".toByteArray())
    }

    fun response(): MapHttpResponseWriter {
        return MapHttpResponseWriter()
    }

    class MapHttpResponseWriter : HttpResponseWriter {

        val collector: MutableMap<String, String> = hashMapOf()

        override fun setStatus(status: Int) {
            collector["status"] = status.toString()
        }

        override fun setHeader(name: String, value: String) {
            collector["header_$name"] = value
        }

        override fun writeBody(data: ByteArray) {
            collector["body"] = String(data)
        }

        fun getStatus(): Int = collector["status"]?.toInt() ?: 0

        fun getHeader(key: String): String = collector["header_$key"] ?: ""

        fun getBody(): String = collector["body"] ?: ""

        fun getBodyAsJsonMap(): Map<String, String> =
                HttpSupport.jsonDeserializer().parse<Map<String, String>>(getBody())
                        ?: emptyMap()

        fun assertStatus(expected: Int) {
            assertThat(getStatus()).isEqualTo(expected)
        }

        fun assertHeader(key: String, expected: String) {
            assertThat(getHeader(key)).isEqualTo(expected)
        }

        fun assertBodyContains(expected: String) {
            assertThat(getBody())
                    .asString()
                    .contains(expected)
        }
    }
}