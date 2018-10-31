package io.imulab.astrea.domain.response.impl

import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.spi.http.HttpHeaders
import io.imulab.astrea.spi.http.UrlValues

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