package io.imulab.astrea.spi.http

/**
 * Abstraction of HTTP response so this sdk does not have to choose an HTTP library for users.
 */
interface HttpResponseWriter {

    /**
     * Set the response status on the HTTP response.
     */
    fun setStatus(status: Int)

    /**
     * Set the header on the HTTP response.
     */
    fun setHeader(name: String, value: String)

    /**
     * Write the given [data] to HTTP response as body.
     */
    fun writeBody(data: ByteArray)
}