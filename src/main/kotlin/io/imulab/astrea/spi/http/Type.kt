package io.imulab.astrea.spi.http

typealias HttpHeaders = Map<String, List<String>>

typealias UrlValues = Map<String, List<String>>

fun UrlValues.singleValue(key: String): String =
        if (this[key] == null || this[key]!!.isEmpty())
            ""
        else
            this[key]!![0]

fun UrlValues.delete(key: String) {
    (this as? MutableMap)?.remove(key)
}