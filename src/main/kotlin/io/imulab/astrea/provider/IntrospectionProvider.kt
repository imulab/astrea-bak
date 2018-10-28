package io.imulab.astrea.provider

import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.spi.HttpRequestReader
import io.imulab.astrea.spi.HttpResponseWriter

/**
 * Interface to provide functions related to token introspection.
 */
interface IntrospectionProvider {
    /**
     * Initiate and create an introspection request.
     */
    fun newIntrospectRequest(reader: HttpRequestReader): IntrospectRequest

    /**
     * Conducts introspection and returns result of the introspection.
     */
    fun newIntrospectResponse(request: IntrospectRequest): IntrospectResponse

    /**
     * Encode successful introspection response to http.
     */
    fun encodeIntrospectReponse(writer: HttpResponseWriter, response: IntrospectResponse)

    /**
     * Encode error introspection response to http.
     */
    fun encodeIntrospectError(writer: HttpResponseWriter, error: Throwable)
}
