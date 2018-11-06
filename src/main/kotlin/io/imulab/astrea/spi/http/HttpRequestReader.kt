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
     * Get the **first** corresponding value of [key] in the http form. Returns empty
     * string if not found.
     */
    @Deprecated("use HttpRequestReader.getForm().mustSingleValue(key) to enforce single value.",
            level = DeprecationLevel.ERROR)
    fun formValue(key: String): String

    @Deprecated("use HttpRequestReader.getForm().mustSingleValue(key) to enforce single value.",
            level = DeprecationLevel.ERROR)
    fun formValueUnescaped(key: String): String

    /**
     * Return the http form.
     */
    fun getForm(): UrlValues

    /**
     * Return the header value, or empty string if it does not exist.
     */
    fun getHeader(key: String): String
}