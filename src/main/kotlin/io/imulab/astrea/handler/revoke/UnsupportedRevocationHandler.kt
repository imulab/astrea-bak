package io.imulab.astrea.handler.revoke

import io.imulab.astrea.domain.TokenType
import io.imulab.astrea.domain.request.RevocationRequest
import io.imulab.astrea.error.RequestParameterInvalidValueException
import io.imulab.astrea.handler.RevocationEndpointHandler

class UnsupportedRevocationHandler(
        private val unsupported: List<TokenType> = emptyList()
) : RevocationEndpointHandler {

    override fun supports(tokenType: TokenType): Boolean = unsupported.contains(tokenType)

    override fun revokeToken(request: RevocationRequest): Boolean {
        throw RequestParameterInvalidValueException.UnsupportedTokenType(request.getTokenType())
    }
}