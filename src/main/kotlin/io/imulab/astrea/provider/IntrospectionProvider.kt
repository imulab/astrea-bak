package io.imulab.astrea.provider

import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.session.Session
import io.imulab.astrea.error.NotSupported
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter

/**
 * Interface to provide functions related to token introspection.
 */
interface IntrospectionProvider {
    /**
     * Initiate and create an introspection request.
     */
    fun newIntrospectRequest(reader: HttpRequestReader, session: Session): IntrospectRequest

    /**
     * Conducts introspection and returns result of the introspection.
     */
    fun newIntrospectResponse(request: IntrospectRequest): IntrospectResponse

    /**
     * Encode successful introspection response to http.
     */
    fun encodeIntrospectResponse(writer: HttpResponseWriter, response: IntrospectResponse)

    /**
     * Encode error introspection response to http.
     */
    fun encodeIntrospectError(writer: HttpResponseWriter, error: Throwable)

    companion object {
        fun notSupported(): IntrospectionProvider = object : IntrospectionProvider {
            override fun newIntrospectRequest(reader: HttpRequestReader, session: Session): IntrospectRequest {
                NotSupported("not supported feature")
            }

            override fun newIntrospectResponse(request: IntrospectRequest): IntrospectResponse {
                NotSupported("not supported feature")
            }

            override fun encodeIntrospectResponse(writer: HttpResponseWriter, response: IntrospectResponse) {
                NotSupported("not supported feature")
            }

            override fun encodeIntrospectError(writer: HttpResponseWriter, error: Throwable) {
                NotSupported("not supported feature")
            }
        }
    }
}
