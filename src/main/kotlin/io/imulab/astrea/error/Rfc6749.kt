package io.imulab.astrea.error

abstract class Rfc6749Exception(
        val error: Rfc6749Error,
        val description: String = "",
        val hint: String = "",
        val debug: String = "",
        val statusCode: Int? = null
) : RuntimeException("[${error.specValue}] description=$description hint=$hint debug=$debug status=${statusCode ?: error.statusCode}") {

    fun getStatusCode(): Int = statusCode ?: error.statusCode

    fun toMap(includeDebug: Boolean = false): Map<String, String> = hashMapOf<String, String>().also { m ->
        m["error"] = error.specValue
        m["status_code"] = (statusCode ?: error.statusCode).toString()
        description.takeIf { it.isNotBlank() }?.let { m["error_description"] = it }
        hint.takeIf { it.isNotBlank() }?.let { m["hint"] = it }
        if (includeDebug)
            debug.takeIf { it.isNotBlank() }?.let { m["debug"] = it }
    }
}

class UnknownRfc6749Exception(wrapped: Throwable): Rfc6749Exception(
        error = Rfc6749Error.Unknown,
        debug = wrapped.message!!
)

enum class Rfc6749Error(val specValue: String, val statusCode: Int) {
    Unknown("unknown", 500),
    InvalidRequestUri("invalid_request_uri", 400),
    InvalidRequestObject("invalid_request_object", 400),
    UnsupportedResponseType("unsupported_response_type", 400),
    // TODO
}

fun Throwable.toRfc6749Error(): Rfc6749Exception {
    return this as? Rfc6749Exception ?: UnknownRfc6749Exception(this)
}