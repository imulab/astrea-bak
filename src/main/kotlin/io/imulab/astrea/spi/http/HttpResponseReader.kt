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
}