package io.imulab.astrea.handler

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.IntrospectRequest
import io.imulab.astrea.domain.response.IntrospectResponse
import io.imulab.astrea.domain.response.impl.DefaultIntrospectResponse

/**
 * Handler for introspection.
 */
interface IntrospectEndpointHandler {

    companion object {
        fun with(vararg handlers: IntrospectEndpointHandler): IntrospectEndpointHandler =
                PrioritizingIntrospectEndpointHandler(handlers.toList())
    }

    /**
     * Returns the token type that this handler inspects
     */
    fun inspects(): Collection<TokenType>

    /**
     * Perform an introspection on [request].
     */
    fun introspectToken(request: IntrospectRequest): IntrospectResponse

    /**
     * This [IntrospectEndpointHandler] delegates work to a list of delegate [IntrospectEndpointHandler]s. Based on the
     * hinted [IntrospectRequest.getTokenType], it will try to prioritize a specific delegate, so it may find a hit
     * sooner. In the worst case, all delegates are visited. If still not found, it will return a [IntrospectResponse]
     * with [IntrospectResponse.isActive] set to false.
     */
    private class PrioritizingIntrospectEndpointHandler(private val delegates: List<IntrospectEndpointHandler>): IntrospectEndpointHandler {

        override fun inspects(): Collection<TokenType> {
            return delegates.flatMap { it.inspects() }.toSet()
        }

        override fun introspectToken(request: IntrospectRequest): IntrospectResponse {
            delegates.sortedWith(Comparator { o1, o2 ->
                when {
                    o1.inspects().contains(request.getTokenType()) -> 1
                    o2.inspects().contains(request.getTokenType()) -> -1
                    else -> 0
                }
            }).forEach {
                val r = it.introspectToken(request)
                if (r.getAccessRequest() != null)
                    return r
            }

            return DefaultIntrospectResponse(active = false, tokenType = request.getTokenType())
        }
    }
}