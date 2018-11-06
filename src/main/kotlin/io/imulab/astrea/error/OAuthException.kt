package io.imulab.astrea.error

/**
 * Base class for errors thrown due to in-conformance to RFC 6749.
 */
abstract class OAuthException(val code: String, private val description: String? = null) :
        RuntimeException("$code ${description ?: ""}".trimEnd(' ', '.')) {

    /**
     * Returns the status code which will be used as the HTTP response status code
     */
    abstract fun statusCode(): Int

    /**
     * Returns the extra headers which will be set in the HTTP response. Default implementation
     * returns no headers.
     */
    open fun extraHeaders(): Map<String, String> = emptyMap()

    /**
     * Returns true if this is caused by response type
     */
    open fun isResponseTypeRelated(): Boolean = false

    /**
     * Return a map representation of this exception.
     */
    fun toMap(includeDebug: Boolean = false): Map<String, String> = hashMapOf<String, String>().also { m ->
        m["error"] = code
        m["status_code"] = statusCode().toString()
        if (description != null)
            m["error_description"] = description
        if (includeDebug) {
            var stackTrace = stackTrace.joinToString("\n") { it.toString() }.replace("&", "")
            if (stackTrace.length > 1500)
                stackTrace = stackTrace.substring(0, 1497) + "..."
            m["stack_trace"] = stackTrace
        }
    }

    /**
     * Thrown when a generic exception happens.
     */
    class ServerException(t: Throwable) : OAuthException("server_error", t.message) {
        override fun statusCode(): Int = 500
    }
}

