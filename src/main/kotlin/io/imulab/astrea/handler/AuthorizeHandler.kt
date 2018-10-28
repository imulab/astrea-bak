package io.imulab.astrea.handler

import io.imulab.astrea.authorize.AuthorizeRequest
import io.imulab.astrea.authorize.AuthorizeResponse

/**
 * Main logic for handling an authorize request.
 */
interface AuthorizeEndpointHandler {

    companion object {
        /**
         * Main entry point to create an [AuthorizeEndpointHandler] with delegates.
         */
        fun with(vararg handlers: AuthorizeEndpointHandler): AuthorizeEndpointHandler =
                DelegatingAuthorizeEndpointHandler(handlers.toList())
    }

    /**
     * Handle the OAuth authorize request. Implementations must exit immediately without
     * modifying any state if it is not capable of handling the [request].
     */
    fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse)

    /**
     * Provides a chain of [AuthorizeHandler] to process [AuthorizeRequest]. By the time that all processors have
     * finished, it checks if all response types have been handled; if not, it throw [IllegalArgumentException].
     */
    private class DelegatingAuthorizeEndpointHandler(private val delegates: List<AuthorizeEndpointHandler>) : AuthorizeEndpointHandler {

        override fun handleAuthorizeRequest(request: AuthorizeRequest, response: AuthorizeResponse) {
            delegates.forEach { it.handleAuthorizeRequest(request, response) }
            if (!request.hasAllResponseTypesBeenHandled())
                throw IllegalArgumentException("unsupported response type.")
        }
    }
}