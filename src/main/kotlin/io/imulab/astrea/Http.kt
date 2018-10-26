package io.imulab.astrea

/**
 * Abstraction of HTTP request so this sdk does not have to choose an HTTP library for users.
 */
interface HttpRequestReader {

    /**
     * Get the **first** corresponding value of [key] in the http form. Returns empty
     * string if not found.
     */
    fun formValue(key: String): String

    fun formValueUnescaped(key: String): String

    /**
     * Return the http form.
     */
    fun getForm(): UrlValues
}

/**
 * Abstraction of HTTP response so this sdk does not have to choose an HTTP library for users.
 */
interface HttpResponseWriter {

}

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

/**
 * Abstraction to use as an http client.
 */
interface HttpClient {
    /**
     * Perform an HTTP Get
     */
    fun get(url: String): HttpResponseReader
}

typealias HttpHeaders = Map<String, List<String>>

typealias UrlValues = Map<String, List<String>>

fun UrlValues.singleValue(key: String): String =
        if (this[key] == null || this[key]!!.isEmpty())
            ""
        else
            this[key]!![0]