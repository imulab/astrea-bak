package io.imulab.astrea.authorize

import io.imulab.astrea.HttpHeaders
import io.imulab.astrea.UrlValues
import java.util.function.Function

/**
 * Response data for the OAuth Authorize Endpoint
 */
interface AuthorizeResponse {

    /**
     * Returns the authorization code
     */
    fun getCode(): String

    /**
     * Returns the response headers.
     */
    fun getHeaders(): HttpHeaders

    /**
     * Add header key value to the response.
     */
    fun addHeader(key: String, value: String)

    /**
     * Returns the query parameters to be encoded in the response.
     */
    fun getQueries(): UrlValues

    /**
     * Add query parameter
     */
    fun addQuery(key: String, value: String)

    /**
     * Returns the fragment values to be encoded in the response.
     */
    fun getFragments(): UrlValues

    /**
     * Add fragment value
     */
    fun addFragment(key: String, value: String)
}

class DefaultAuthorizeResponse(private val headers: MutableMap<String, MutableList<String>> = mutableMapOf(),
                               private val queries: MutableMap<String, MutableList<String>> = mutableMapOf(),
                               private val fragments: MutableMap<String, MutableList<String>> = mutableMapOf(),
                               private var code: String = "") : AuthorizeResponse {
    override fun getCode(): String = this.code

    override fun getHeaders(): HttpHeaders = this.headers.mapValues { it.value.toList() }

    override fun addHeader(key: String, value: String) {
        headers.computeIfAbsent(key) { mutableListOf() }
        headers[key]!!.add(value)
    }

    override fun getQueries(): UrlValues = this.queries.mapValues { it.value.toList() }

    override fun addQuery(key: String, value: String) {
        if (key == "code")
            this.code = value
        queries.computeIfAbsent(key) { mutableListOf() }
        queries[key]!!.add(value)
    }

    override fun getFragments(): UrlValues = this.fragments.mapValues { it.value.toList() }

    override fun addFragment(key: String, value: String) {
        if (key == "code")
            this.code = value
        fragments.computeIfAbsent(key) { mutableListOf() }
        fragments[key]!!.add(value)
    }
}