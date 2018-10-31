package io.imulab.astrea.spi.http

/**
 * Abstraction to use as an http client.
 */
interface HttpClient {
    /**
     * Perform an HTTP Get
     */
    fun get(url: String): HttpResponseReader
}