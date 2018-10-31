package io.imulab.astrea.domain.response

import io.imulab.astrea.spi.http.HttpHeaders
import io.imulab.astrea.spi.http.UrlValues

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
