package io.imulab.astrea.spi.http

/**
 * Abstraction of HTTP request so this sdk does not have to choose an HTTP library for users.
 */
interface HttpRequestReader {

    /**
     * Return upper cased http method
     */
    fun method(): String

    /**
     * Return the http form.
     */
    fun getForm(): UrlValues

    /**
     * Return the header value, or empty string if it does not exist.
     */
    fun getHeader(key: String): String
}