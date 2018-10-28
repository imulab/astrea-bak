package io.imulab.astrea.handler

import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse

/**
 * Main logic for handling an token endpoint request.
 */
interface TokenEndpointHandler {

    companion object {
        /**
         * Main entry point to create an [AuthorizeHandler] with delegates.
         */
        fun with(vararg handlers: TokenEndpointHandler): TokenEndpointHandler =
                TokenEndpointHandler.DelegatingTokenEndpointHandler(handlers.toList())
    }

    /**
     * Handles a OAuth Token Endpoint access request. Implementations should return false immediately if it cannot
     * handle this type of access request.
     *
     * Returns true if handled.
     */
    fun handleAccessRequest(request: AccessRequest): Boolean

    /**
     * Populates the return information on the access request. Returns true if populated.
     */
    fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean

    private class DelegatingTokenEndpointHandler(private val delegates: List<TokenEndpointHandler>): TokenEndpointHandler {

        override fun handleAccessRequest(request: AccessRequest): Boolean {
            val hasHandler = delegates.firstOrNull { it.handleAccessRequest(request) } != null
            if (!hasHandler)
                throw RuntimeException("TODO: no handler for token endpoint request.")
            return hasHandler
        }

        override fun populateAccessResponse(request: AccessRequest, response: AccessResponse): Boolean {
            delegates.forEach{ it.populateAccessResponse(request, response) }
            return true
        }
    }
}