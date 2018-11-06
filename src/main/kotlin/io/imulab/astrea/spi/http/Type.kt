package io.imulab.astrea.spi.http

import io.imulab.astrea.error.RequestParameterMissingException
import io.imulab.astrea.error.RequestParameterRepeatedException

typealias HttpHeaders = Map<String, List<String>>

typealias UrlValues = Map<String, List<String>>

fun UrlValues.mustSingleValue(key: String): String {
    if (!this.containsKey(key) || this[key]!!.isEmpty())
        throw RequestParameterMissingException(key)
    else if (this[key]!!.size > 1)
        throw RequestParameterRepeatedException(key)
    else
        return this[key]!![0]
}

fun UrlValues.singleValue(key: String): String =
        if (this[key] == null || this[key]!!.isEmpty())
            ""
        else
            this[key]!![0]

fun UrlValues.delete(key: String) {
    (this as? MutableMap)?.remove(key)
}