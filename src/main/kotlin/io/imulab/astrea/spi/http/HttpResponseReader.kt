package io.imulab.astrea.spi.http

/**
 * Abstraction to Http response so [HttpClient] abstraction can read response.
 */
interface HttpResponseReader {
    /**
     * Returns the HTTP response status
     */
    fun statusCode(): Int

    /**
     * Returns response body as an byte array.
     */
    fun body(): ByteArray

    /**
     * Ensures the return status is [expected]. If it is not, an [IllegalStateException] is thrown with
     * the string format of status as its message. Caller can provide a custom [exceptionEnhancer] to switch
     * the exception for more context. If the status check is okay, returns this object for further processing.
     */
    fun ensureStatus(
            expected: Int,
            exceptionEnhancer: ((IllegalStateException) -> Throwable)? = null
    ): HttpResponseReader {
        if (expected != statusCode())
            throw IllegalStateException(statusCode().toString())
                    .let { if (exceptionEnhancer != null) exceptionEnhancer(it) else it }
        return this
    }
}