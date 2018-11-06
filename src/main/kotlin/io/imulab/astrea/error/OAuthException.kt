package io.imulab.astrea.error

/**
 * Base class for errors thrown due to in-conformance to RFC 6749.
 */
abstract class OAuthException(val code: String, val description: String? = null):
        RuntimeException("$code ${description ?: ""}".trimEnd(' ', '.'))

