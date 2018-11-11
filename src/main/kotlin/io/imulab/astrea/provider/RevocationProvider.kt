package io.imulab.astrea.provider

import io.imulab.astrea.error.NotSupported
import io.imulab.astrea.spi.http.HttpRequestReader
import io.imulab.astrea.spi.http.HttpResponseWriter

/**
 * Interface to provide functions related to token revocation.
 */
interface RevocationProvider {
    /**
     * Handle the incoming revocation http request and perform a revocation if necessary.
     */
    fun revoke(reader: HttpRequestReader)

    /**
     * Encode http revocation response, either as a success, or with the supplied [error].
     */
    fun encodeRevocationResponse(writer: HttpResponseWriter, error: Throwable?)

    companion object {
        fun notSupported(): RevocationProvider = object : RevocationProvider {
            override fun revoke(reader: HttpRequestReader) {
                NotSupported("not supported feature")
            }

            override fun encodeRevocationResponse(writer: HttpResponseWriter, error: Throwable?) {
                NotSupported("not supported feature")
            }
        }
    }
}

