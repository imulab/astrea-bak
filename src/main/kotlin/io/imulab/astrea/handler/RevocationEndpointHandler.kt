package io.imulab.astrea.handler

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.RevocationRequest

interface RevocationEndpointHandler {

    companion object {
        fun with(vararg handlers: RevocationEndpointHandler): RevocationEndpointHandler =
                PrioritizingRevocationEndpointHandler(handlers.toList())
    }

    /**
     * Returns true if this handler supports revoking the given [tokenType].
     */
    fun supports(tokenType: TokenType): Boolean

    /**
     * Perform revocation on a token. Returns true if the token has been successfully revoked.
     */
    fun revokeToken(request: RevocationRequest): Boolean

    private class PrioritizingRevocationEndpointHandler(
            private val delegates: List<RevocationEndpointHandler>
    ): RevocationEndpointHandler {
        override fun supports(tokenType: TokenType): Boolean =
                this.delegates.any { it.supports(tokenType) }

        override fun revokeToken(request: RevocationRequest): Boolean {
            return delegates.sortedWith(Comparator { o1, o2 ->
                when {
                    o1.supports(request.getTokenType()) -> 1
                    o2.supports(request.getTokenType()) -> -1
                    else -> 0
                }
            }).find { it.revokeToken(request) }?.let { true } ?: false
        }
    }
}