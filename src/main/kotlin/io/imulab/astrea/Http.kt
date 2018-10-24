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

typealias HttpHeaders = Map<String, List<String>>

typealias UrlValues = Map<String, List<String>>