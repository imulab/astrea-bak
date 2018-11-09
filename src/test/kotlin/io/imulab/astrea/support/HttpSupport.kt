package io.imulab.astrea.support

import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.UrlValues
import org.mockito.Mockito.*

object HttpSupport {

    fun request(method: String = "POST",
                headers: Map<String, String> = emptyMap(),
                forms: UrlValues = emptyMap()): HttpRequestReader {
        val reader = mock(HttpRequestReader::class.java)
        `when`(reader.method()).thenReturn(method)
        headers.forEach { t, u -> `when`(reader.getHeader(t)).thenReturn(u) }
        `when`(reader.getForm()).thenReturn(forms)
        return reader
    }
}