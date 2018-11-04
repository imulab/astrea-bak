package io.imulab.astrea.handler

import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse

/**
 * Main logic for handling an token endpoint request.
 */
interface TokenEndpointHandler {

    companion object {
        /**
         * Main entry point to create an [TokenEndpointHandler] with delegates.
         */
        fun with(vararg handlers: TokenEndpointHandler): TokenEndpointHandler =
                TokenEndpointHandler.DelegatingTokenEndpointHandler(handlers.toList())
    }

    /**
     * Probe method to test if the [TokenEndpointHandler] supports processing [request].
     */
    fun supports(request: AccessRequest): Boolean

    /**
     * Handles a OAuth Token Endpoint access request. Implementations should return false immediately if it cannot
     * handle this type of access request.
     */
    fun handleAccessRequest(request: AccessRequest)

    /**
     * Populates the return information on the access request. Returns true if populated.
     */
    fun populateAccessResponse(request: AccessRequest, response: AccessResponse)

    private class DelegatingTokenEndpointHandler(private val delegates: List<TokenEndpointHandler>) : TokenEndpointHandler {

        override fun supports(request: AccessRequest): Boolean = true

        override fun handleAccessRequest(request: AccessRequest) {
            val handlers = delegates.filter { it.supports(request) }.takeIf { it.isNotEmpty() }
                    ?: throw RuntimeException("TODO: no handler for token endpoint request.")
            handlers.forEach { it.handleAccessRequest(request) }
        }

        // TODO?
        override fun populateAccessResponse(request: AccessRequest, response: AccessResponse) {
            delegates.forEach { it.populateAccessResponse(request, response) }
        }
    }
}